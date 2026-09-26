use super::http::*;
use crate::h2_fingerprint::h2::ConnectionData;
use crate::{h1_fingerptint, h2_fingerprint};

use crate::tls_fingerprint;
use crate::{Data, ProxyConfig};

use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use anyhow::Result;

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

pub async fn connection(config: ProxyConfig) -> Result<()> {
    let addr = format!("127.0.0.1:{}", config.port);
    let socket = TcpListener::bind(addr).await?;

    println!("[TCP] Listening on {}", config.port);
    loop {
        let (client, addr) = socket.accept().await?;

        let data = config.ctx.clone();

        println!("[TCP] New Connection: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle(client, data).await {
                eprintln!("[TCP] Error: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, handle: Data) -> Result<()> {
    let mut buff: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024];
    let packet = loop {
        let n = client.read(&mut buf).await?;

        if n == 0 {
            return Err(anyhow::anyhow!("[TCP] Connection closed"));
        }

        buff.extend_from_slice(&buf[..n]);

        if buff.len() > 8192 {
            return Err(anyhow::anyhow!("[TCP] HTTP Header too large"));
        }

        match HttpPacket::parse(&buff)? {
            ParseResult::Complete(p) => break p,
            ParseResult::Partial => continue,
        }
    };
    let packet = Arc::new(packet);

    match HttpPacket::check_method(packet.clone(), client).await? {
        ConnectionStatus::Success(stream) => client = stream,
        ConnectionStatus::Failure(reason) => {
            eprintln!("[HTTP] {}", reason);
            return Ok(());
        }
    }

    let remote = match upstream_connect(packet.clone(), handle.upstream.clone()).await? {
        ConnectionStatus::Success(stream) => stream,
        ConnectionStatus::Failure(reason) => {
            eprintln!("[TCP] Connection failure: {}", reason);
            let _ = client.write_all(HTTP_502_BAD_GATEWAY).await;
            return Ok(());
        }
    };

    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let sni = get_sni_from_packet(packet.clone())?;

    let (remote, selected_alpn) = tls_fingerprint::tls::create_ssl_acceptor_upstream(
        remote,
        &sni,
        handle.tls.clone(),
        handle.http2.clone(),
    )
    .await?;

    client.write_all(HTTP_200_OK).await?;

    let acceptor = tls_fingerprint::tls::create_ssl_acceptor(handle.ca, &selected_alpn)?;

    let client = tls_fingerprint::tls::handle_tls(client, acceptor).await?;

    let proxydata = ConnectionData {
        tls: handle.tls,
        http2: handle.http2,
        http1: handle.http1,
        upstream: handle.upstream,
        sni: Arc::new(sni),
        selected_alpn: Arc::new(selected_alpn),
        packet,
    };

    match proxydata.selected_alpn.as_deref() {
        Some([_, b'h', b'2']) => {
            h2_fingerprint::h2::handle_h2(client, remote, proxydata).await?;
        }
        _ => h1_fingerptint::h1::handle_h1(client, remote, proxydata).await?,
    }

    Ok(())
}

pub async fn upstream_connect(
    packet: Arc<HttpPacket>,
    upstream: Arc<Option<String>>,
) -> Result<ConnectionStatus> {
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

fn get_sni_from_packet(packet: Arc<HttpPacket>) -> Result<String> {
    let host = match packet.get_header("host") {
        Some(h) => h,
        None => return Err(anyhow::anyhow!("Host header not found")),
    };
    let sni = host.split(":").next().unwrap_or(host);
    Ok(sni.to_string())
}

pub async fn upstream_connect_helper(host: &str, upstream: &str) -> Result<ConnectionStatus> {
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
