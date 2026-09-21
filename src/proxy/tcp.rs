use std::error::Error;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::http;
use crate::tls;
use crate::tls::cert::MitmCa;

const HTTP_502_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
Content-Type: text/plain\r\n\
Content-Length: 25\r\n\
Connection: close\r\n\
\r\n\
502 Bad Gateway: Upstream Error";

const HTTP_200_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

use super::http::{HttpPacket, ParseResult};

pub enum ConnectionStatus {
    Success(TcpStream),
    Failure(String),
}

pub async fn connection(
    ca: Arc<MitmCa>,
    upstream: Arc<Option<String>>,
    port: u16,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let addr = format!("127.0.0.1:{}", port);
    let socket = TcpListener::bind(addr).await?;
    println!("[TCP] Listening on {}", port);

    loop {
        let (client, addr) = socket.accept().await?;
        let ca_clone = ca.clone();
        let upsteam_clone = upstream.clone();
        println!("[TCP] New Connection: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle(client, ca_clone, upsteam_clone).await {
                eprintln!("[TCP] Error: {e}");
            }
        });
    }
}

async fn handle(
    mut client: TcpStream,
    ca: Arc<MitmCa>,
    upstream: Arc<Option<String>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let ca_clone = Arc::clone(&ca);
    let mut buf = [0u8; 1024];
    let packet = loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Err("[TCP] Connection closed".into());
        }
        match http::parse(&buf[..n])? {
            ParseResult::Complete(p) => break p,
            ParseResult::Partial => continue,
        }
    };

    let remote = match connect_proxy(packet, upstream).await? {
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

    let acceptor = tls::tls::create_ssl_acceptor(ca_clone, tx)?;
    let mut client = tls::tls::handle_tls(client, acceptor).await?;
    let sni = rx.recv().await.unwrap_or_else(|| "unknown".to_string());
    let mut remote = tls::tls::create_ssl_acceptor_upstream(remote, &sni).await?;

    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;

    Ok(())
}

async fn connect_proxy(
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
        Some(proxy_addr) => {
            let mut stream = match TcpStream::connect(proxy_addr).await {
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

            let mut buf = [0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    return Ok(ConnectionStatus::Failure(format!(
                        "Proxy Failed to read response: {}",
                        e
                    )));
                }
            };

            let response = String::from_utf8_lossy(&buf[..n]);
            if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
                return Ok(ConnectionStatus::Failure(format!(
                    "Proxy rejected: {}",
                    response.lines().next().unwrap_or("unknown")
                )));
            }

            Ok(ConnectionStatus::Success(stream))
        }

        None => match TcpStream::connect(&host).await {
            Ok(stream) => Ok(ConnectionStatus::Success(stream)),
            Err(e) => Ok(ConnectionStatus::Failure(e.to_string())),
        },
    }
}
