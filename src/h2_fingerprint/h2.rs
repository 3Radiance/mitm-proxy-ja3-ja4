use anyhow::Result;
use crate::config::*;
use crate::h2_fingerprint::upstream::*;
use crate::proxy::http::HttpPacket;

use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_btls::SslStream;

use super::request::*;

#[derive(Clone)]
pub struct ConnectionData {
    pub tls: Arc<TlsConfig>,
    pub http2: Arc<Http2Config>,
    pub http1: Arc<Http1Config>,
    pub upstream: Arc<Option<String>>,
    pub sni: Arc<String>,
    pub selected_alpn: Arc<Option<Vec<u8>>>,
    pub packet: Arc<HttpPacket>,
}

pub async fn handle_h2(
    client: SslStream<TcpStream>,
    remote: SslStream<TcpStream>,
    proxydata: ConnectionData,
) -> Result<()> {
    let mut server_conn = http2::server::handshake(client).await?;

    let upstream_builder = build_upstream_h2_builder(proxydata.http2.clone()).await?;

    let (upstream_send, upstream_conn) = upstream_builder.handshake::<_, Bytes>(remote).await?;

    let upstream_send = Arc::new(Mutex::new(upstream_send));

    tokio::spawn(async move {
        if let Err(err) = upstream_conn.await {
            eprintln!("[H2] Upstream h2 connection error: {err}");
        }
    });

    while let Some(res) = server_conn.accept().await {
        let (request, respond) = res?;

        let upstream_send = upstream_send.clone();
        let proxydata = proxydata.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_request(request, respond, upstream_send, proxydata).await {
                eprintln!("[H2] request handling failed: {err:?}");
            }
        });
    }

    Ok(())
}
