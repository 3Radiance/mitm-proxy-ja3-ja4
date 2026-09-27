use crate::config::*;
use crate::h2_fingerprint::upstream::*;
use crate::proxy::http::HttpPacket;
use crate::tls_fingerprint::ech::EchCache;
use anyhow::Result;

use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Duration;
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
    pub cache: Arc<EchCache>,
}

pub async fn handle_h2(
    client: SslStream<TcpStream>,
    remote: SslStream<TcpStream>,
    proxydata: ConnectionData,
) -> Result<()> {
    let upstream_builder = build_upstream_h2_builder(proxydata.http2.clone()).await?;

    let (server_res, upstream_res) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(5), http2::server::handshake(client)),
        tokio::time::timeout(
            Duration::from_secs(5),
            upstream_builder.handshake::<_, Bytes>(remote)
        )
    );

    let mut server_conn =
        server_res.map_err(|_| anyhow::anyhow!("client h2 handshake timeout"))??;

    let (upstream_send, upstream_conn) =
        upstream_res.map_err(|_| anyhow::anyhow!("upstream h2 handshake timeout"))??;

    let upstream_send = Arc::new(Mutex::new(upstream_send));

    tokio::spawn(async move {
        if let Err(err) = upstream_conn.await {
            crate::log_tag!(error, "H2", "Upstream h2 connection error: {err}");
        }
    });

    while let Some(res) = server_conn.accept().await {
        let (request, respond) = res?;

        let upstream_send = upstream_send.clone();
        let proxydata = proxydata.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_request(request, respond, upstream_send, proxydata).await {
                crate::log_tag!(error, "H2", "Request handling failed: {err:?}");
            }
        });
    }

    Ok(())
}
