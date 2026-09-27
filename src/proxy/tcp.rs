use super::http::*;
use crate::h2_fingerprint::h2::ConnectionData;
use crate::{h1_fingerprint, h2_fingerprint};

use crate::tls_fingerprint;
use crate::{Data, ProxyConfig};

use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use tokio::time::Duration;

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

    crate::log_tag!(info, "TCP", "Listening on {}", config.port);
    loop {
        let (client, addr) = socket.accept().await?;

        let data = config.ctx.clone();

        crate::log_tag!(info, "TCP", "New connection: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle(client, data).await {
                crate::log_tag!(error, "TCP", "Error: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, handle: Data) -> Result<()> {
    let mut buff: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024];
    let packet = loop {
        let n = tokio::time::timeout(Duration::from_secs(10), client.read(&mut buf)).await??;

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
            crate::log_tag!(warn, "HTTP", "{}", reason);
            return Ok(());
        }
    }

    let host = match packet.get_header("host") {
        Some(h) => h,
        None => {
            return Err(anyhow::anyhow!("Host header not found".to_string(),));
        }
    };

    crate::log_tag!(
        info,
        "TCP",
        "Opening upstream connection for host: {}",
        host
    );

    let remote = match upstream_connect(host, handle.upstream.clone()).await? {
        ConnectionStatus::Success(stream) => stream,
        ConnectionStatus::Failure(reason) => {
            crate::log_tag!(warn, "TCP", "Connection failure: {}", reason);
            let _ = client.write_all(HTTP_502_BAD_GATEWAY).await;
            return Ok(());
        }
    };

    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let sni = get_sni_from_packet(packet.clone())?;
    crate::log_tag!(
        info,
        "TLS",
        "Starting upstream TLS handshake for SNI: {}",
        sni
    );

    let (remote, selected_alpn) = tls_fingerprint::tls::create_ssl_acceptor_upstream(
        remote,
        &sni,
        handle.tls.clone(),
        handle.http2.clone(),
        true,
        handle.upstream.clone(),
        handle.cache.clone(),
    )
    .await?;

    client.write_all(HTTP_200_OK).await?;

    let alpn_debug = selected_alpn
        .as_deref()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<none>".to_string());
    crate::log_tag!(
        info,
        "TLS",
        "Upstream TLS negotiated for {} with ALPN: {}",
        sni,
        alpn_debug
    );

    let acceptor = tls_fingerprint::tls::create_ssl_acceptor(handle.ca, &selected_alpn)?;

    let client = tls_fingerprint::tls::handle_tls(client, acceptor).await?;
    crate::log_tag!(
        info,
        "TLS",
        "Client-side TLS handshake completed for {}",
        sni
    );

    let proxydata = ConnectionData {
        tls: handle.tls,
        http2: handle.http2,
        http1: handle.http1,
        upstream: handle.upstream,
        sni: Arc::new(sni.clone()),
        selected_alpn: Arc::new(selected_alpn),
        packet,
        cache: handle.cache,
    };

    match proxydata.selected_alpn.as_deref() {
        Some([_, b'h', b'2']) => {
            crate::log_tag!(info, "H2", "Selected protocol for {}: h2", sni);
            h2_fingerprint::h2::handle_h2(client, remote, proxydata).await?;
        }
        _ => {
            crate::log_tag!(info, "H1", "Selected protocol for {}: h1", sni);
            h1_fingerprint::h1::handle_h1(client, remote, proxydata).await?;
        }
    }

    Ok(())
}

pub async fn upstream_connect(
    host: &str,
    upstream: Arc<Option<String>>,
) -> Result<ConnectionStatus> {
    match &*upstream {
        Some(proxy_addr) => upstream_connect_helper(host, proxy_addr).await,
        None => {
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&host)).await? {
                Ok(stream) => Ok(ConnectionStatus::Success(stream)),
                Err(e) => Ok(ConnectionStatus::Failure(e.to_string())),
            }
        }
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
    crate::log_tag!(
        debug,
        "TCP",
        "Connecting to upstream proxy {} for host {}",
        upstream,
        host
    );

    let mut stream =
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&upstream)).await? {
            Ok(s) => s,
            Err(e) => return Ok(ConnectionStatus::Failure(e.to_string())),
        };

    let connect_request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", host, host);

    if let Err(e) = tokio::time::timeout(
        Duration::from_secs(5),
        stream.write_all(connect_request.as_bytes()),
    )
    .await?
    {
        return Ok(ConnectionStatus::Failure(format!(
            "Proxy Failed to send CONNECT: {}",
            e
        )));
    }

    let mut buff: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024];

    let response_packet = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
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
        crate::log_tag!(
            debug,
            "TCP",
            "Upstream proxy CONNECT accepted for {} with status {}",
            host,
            response_packet.code
        );
        Ok(ConnectionStatus::Success(stream))
    } else {
        let reason = format!(
            "Proxy returned status {}: {}",
            response_packet.code, response_packet.reason
        );
        crate::log_tag!(
            warn,
            "TCP",
            "Upstream proxy CONNECT rejected for {}: {}",
            host,
            reason
        );
        Ok(ConnectionStatus::Failure(reason))
    }
}
