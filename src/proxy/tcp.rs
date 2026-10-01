use super::http::*;
use crate::config::TcpConfig;
use crate::h2_fingerprint::h2::ConnectionData;
use crate::{h1_fingerprint, h2_fingerprint};
use std::pin::Pin;
use tokio_btls::SslStream;

use crate::tls_fingerprint;
use crate::{Data, ProxyConfig};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
};

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

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

pub struct Router {
    pub default: Data,
    pub domains: Arc<HashMap<String, Data>>,
}

impl Router {
    pub fn resolve(&self, sni: &str) -> Data {
        if let Some(d) = self.lookup(sni) {
            return d.clone();
        }
        self.default.clone()
    }

    fn lookup(&self, sni: &str) -> Option<&Data> {
        let key = sni.trim_end_matches('.').to_ascii_lowercase();

        if let Some(d) = self.domains.get(&key) {
            return Some(d);
        }

        let domain = addr::parse_domain_name(&key).ok()?;
        let root = domain.root()?;
        let suffix = domain.suffix();
        let prefix = domain.prefix();

        if key != root {
            let candidate = format!("*.{root}");
            if let Some(d) = self.domains.get(&candidate) {
                return Some(d);
            }
        }

        if let Some(label) = root.strip_suffix(&format!(".{suffix}")) {
            let candidate = format!("{label}.*");
            if let Some(d) = self.domains.get(&candidate) {
                return Some(d);
            }

            let candidate = format!("*.{label}.*");
            if let Some(d) = self.domains.get(&candidate) {
                return Some(d);
            }

            if let Some(p) = prefix {
                let candidate = format!("{p}.{label}.*");
                if let Some(d) = self.domains.get(&candidate) {
                    return Some(d);
                }
            }
        }

        None
    }
}

pub async fn connection(config: ProxyConfig) -> Result<()> {
    let addr = format!("127.0.0.1:{}", config.port);
    let socket = TcpListener::bind(addr).await?;

    crate::log_tag!(info, "TCP", "Listening on {}", config.port);
    loop {
        let (client, addr) = socket.accept().await?;

        let router = Arc::clone(&config.router);

        crate::log_tag!(info, "TCP", "New connection: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle(client, router).await {
                crate::log_tag!(error, "TCP", "Error: {e}");
            }
        });
    }
}

async fn handle(client: TcpStream, router: Arc<Router>) -> Result<()> {
    let mut client = client;
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

    let host = packet
        .get_header("host")
        .ok_or_else(|| anyhow::anyhow!("Host header not found"))?;

    crate::log_tag!(
        info,
        "TCP",
        "Opening upstream connection for host: {}",
        host
    );

    let sni = get_sni_from_packet(packet.clone())?;

    let handle: Data = router.resolve(&sni);

    let remote = match upstream_connect(host, handle.upstream.clone(), handle.tcp.clone()).await? {
        ConnectionStatus::Success(stream) => stream,
        ConnectionStatus::Failure(reason) => {
            crate::log_tag!(warn, "TCP", "Connection failure: {}", reason);
            let _ = client.write_all(HTTP_502_BAD_GATEWAY).await;
            return Ok(());
        }
    };

    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let remote_ssl = tls_fingerprint::tls::create_ssl_acceptor_upstream(handle.tls.clone()).await?;

    let mut ssl = remote_ssl.configure()?.into_ssl(&sni)?;

    tls_fingerprint::helpers::set_alps(&mut ssl, handle.http2.clone(), handle.tls.clone());
    tls_fingerprint::ech::set_ech(
        &mut ssl,
        handle.tls.clone(),
        handle.tcp.clone(),
        handle.http2.clone(),
        &sni,
        handle.upstream.clone(),
        handle.cache.clone(),
    )
    .await?;

    let mut remote = SslStream::new(ssl, remote)?;

    tokio::time::timeout(Duration::from_secs(5), Pin::new(&mut remote).connect()).await??;

    let alpn = remote.ssl().selected_alpn_protocol().map(|p| {
        let mut wire = Vec::with_capacity(1 + p.len());
        wire.push(p.len() as u8);
        wire.extend_from_slice(p);
        wire
    });

    client.write_all(HTTP_200_OK).await?;

    let acceptor = tls_fingerprint::tls::create_ssl_acceptor(handle.ca, &alpn)?;

    let client = tls_fingerprint::tls::handle_tls(client, acceptor).await?;

    crate::log_tag!(
        info,
        "TLS",
        "Client-side TLS handshake completed for {}",
        sni
    );

    let proxydata = ConnectionData {
        tls: handle.tls,
        tcp: handle.tcp,
        http2: handle.http2,
        http1: handle.http1,
        upstream: handle.upstream,
        sni: Arc::new(sni.clone()),
        selected_alpn: Arc::new(alpn),
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
    tcp: Arc<TcpConfig>,
) -> Result<ConnectionStatus> {
    match &*upstream {
        Some(proxy_addr) => upstream_connect_helper(host, proxy_addr).await,
        None => {
            if let Some(mark) = tcp.mark {
                match tokio::time::timeout(Duration::from_secs(5), set_mark(mark, host)).await? {
                    Ok(stream) => Ok(ConnectionStatus::Success(stream)),
                    Err(e) => Ok(ConnectionStatus::Failure(e.to_string())),
                }
            } else {
                match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&host))
                    .await?
                {
                    Ok(stream) => Ok(ConnectionStatus::Success(stream)),
                    Err(e) => Ok(ConnectionStatus::Failure(e.to_string())),
                }
            }
        }
    }
}

fn get_sni_from_packet(packet: Arc<HttpPacket>) -> Result<String> {
    let host = packet
        .get_header("host")
        .ok_or_else(|| anyhow::anyhow!("Host header not found"))?;
    let host = host.trim();

    let sni = if let Some(rest) = host.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 host"))?;
        &rest[..end]
    } else {
        host.split(':')
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed split host"))?
    };

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

async fn set_mark(mark: u32, host: &str) -> Result<TcpStream> {
    let addr: SocketAddr = lookup_host(host)
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for {host}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No IP addresses found for {host}"))?;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| anyhow::anyhow!("Socket creation failed: {e}"))?;

    socket
        .set_mark(mark)
        .map_err(|e| anyhow::anyhow!("Failed to set SO_MARK ({mark}): {e}"))?;

    socket
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("Set nonblocking failed: {e}"))?;

    match socket.connect(&addr.into()) {
        Ok(_) => {}
        Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(anyhow::anyhow!("Connect error: {e}")),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)
        .map_err(|e| anyhow::anyhow!("Tokio conversion failed: {e}"))?;

    let handshake_future = async {
        stream.writable().await?;
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }
        Ok::<(), std::io::Error>(())
    };

    match tokio::time::timeout(Duration::from_secs(5), handshake_future).await {
        Ok(Ok(())) => Ok(stream),
        Ok(Err(e)) => Err(anyhow::anyhow!("Handshake failed: {e}")),
        Err(_) => Err(anyhow::anyhow!("Connection timed out")),
    }
}
