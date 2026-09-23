use super::http::*;
use crate::config::*;
use crate::fingerprint;
use crate::fingerprint::cert::MitmCa;
use std::error::Error;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const HTTP_502_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
Content-Type: text/plain\r\n\
Content-Length: 25\r\n\
Connection: close\r\n\
\r\n\
502 Bad Gateway: Upstream Error";

pub const HTTP_200_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

pub const HTTP_403_FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

pub enum ConnectionStatus {
    Success(TcpStream),
    Failure(String),
}

pub async fn connection(config: AppConfig) -> Result<(), Box<dyn Error + Send + Sync>> {
    let profile = config
        .profiles
        .values()
        .next()
        .ok_or("No Profile Configured")?;

    let tls = Arc::new(profile.tls.clone());
    let http2 = Arc::new(profile.http2.clone());
    let upstream = Arc::new(profile.config.upstream_proxy.clone());
    let ca = Arc::new(MitmCa::load_or_create(
        &profile.config.cert,
        &profile.config.key,
    )?);
    let addr = format!("127.0.0.1:{}", profile.config.port);
    let socket = TcpListener::bind(addr).await?;

    println!("[TCP] Listening on {}", profile.config.port);
    loop {
        let (client, addr) = socket.accept().await?;

        let tls_clone = Arc::clone(&tls);
        let http2_clone = Arc::clone(&http2);
        let ca_clone = Arc::clone(&ca);
        let upstream_clone = Arc::clone(&upstream);

        println!("[TCP] New Connection: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle(client, ca_clone, tls_clone, http2_clone, upstream_clone).await {
                eprintln!("[TCP] Error: {e}");
            }
        });
    }
}

async fn handle(
    mut client: TcpStream,
    ca: Arc<MitmCa>,
    tls: Arc<TlsConfig>,
    http2: Arc<Http2Config>,
    upstream: Arc<Option<String>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut buff: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024];
    let packet = loop {
        let n = client.read(&mut buf).await?;

        if n == 0 {
            return Err("[TCP] Connection closed".into());
        }

        buff.extend_from_slice(&buf[..n]);

        if buff.len() > 8192 {
            return Err("[TCP] HTTP Header too large".into());
        }

        match HttpPacket::parse(&buff)? {
            ParseResult::Complete(p) => break p,
            ParseResult::Partial => continue,
        }
    };

    match HttpPacket::check_method(&packet, client).await? {
        ConnectionStatus::Success(stream) => client = stream,
        ConnectionStatus::Failure(reason) => {
            eprintln!("[HTTP] {}", reason);
            return Ok(());
        }
    }

    let remote = match upstream_connect(packet, upstream).await? {
        ConnectionStatus::Success(stream) => stream,
        ConnectionStatus::Failure(reason) => {
            eprintln!("[TCP] Connection failure: {}", reason);
            let _ = client.write_all(HTTP_502_BAD_GATEWAY).await;
            return Ok(());
        }
    };
    client.write_all(HTTP_200_OK).await?;
    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let tls1 = Arc::clone(&tls);
    let tls2 = Arc::clone(&tls);

    let acceptor = fingerprint::tls::create_ssl_acceptor(ca, tx, tls1)?;
    let (mut client, selected_alpn) = fingerprint::tls::handle_tls(client, acceptor).await?;
    let sni = rx.recv().await.unwrap_or_else(|| "unknown".to_string());
    let mut remote =
        fingerprint::tls::create_ssl_acceptor_upstream(remote, &sni, tls2, selected_alpn).await?;

    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;

    Ok(())
}

async fn upstream_connect(
    packet: HttpPacket,
    upstream: Arc<Option<String>>,
) -> Result<ConnectionStatus, Box<dyn Error + Send + Sync>> {
    let host = match packet.get_header("host") {
        Some(h) => h,
        None => {
            return Ok(ConnectionStatus::Failure(
                "Host header not found".to_string(),
            ));
        }
    };

    match &*upstream {
        Some(proxy_addr) => upstream_connect_helper(host, proxy_addr).await,
        None => match TcpStream::connect(&host).await {
            Ok(stream) => Ok(ConnectionStatus::Success(stream)),
            Err(e) => Ok(ConnectionStatus::Failure(e.to_string())),
        },
    }
}

async fn upstream_connect_helper(
    host: &str,
    upstream: &str,
) -> Result<ConnectionStatus, Box<dyn Error + Send + Sync>> {
    let mut stream = match TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => return Ok(ConnectionStatus::Failure(e.to_string())),
    };

    let connect_request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", host, host);

    if let Err(e) = stream.write_all(connect_request.as_bytes()).await {
        return Ok(ConnectionStatus::Failure(format!(
            "Proxy Failed to send CONNECT: {}",
            e
        )));
    }

    let mut buff: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024];

    let response_packet = loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(ConnectionStatus::Failure(
                "Proxy closed connection".to_string(),
            ));
        }
        buff.extend_from_slice(&buf[..n]);

        if buff.len() > 8192 {
            return Ok(ConnectionStatus::Failure(
                "Proxy response too large".to_string(),
            ));
        }

        match HttpPacketRes::parse(&buff)? {
            ParseResult::Complete(p) => break p,
            ParseResult::Partial => continue,
        }
    };

    if response_packet.code == 200 {
        Ok(ConnectionStatus::Success(stream))
    } else {
        Ok(ConnectionStatus::Failure(format!(
            "Proxy returned status {}: {}",
            response_packet.code, response_packet.reason
        )))
    }
}
