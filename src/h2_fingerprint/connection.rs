use crate::h2_fingerprint::h2::ConnectionData;
use crate::h2_fingerprint::upstream::*;

use bytes::Bytes;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type UpstreamSend = http2::client::SendRequest<Bytes>;

pub async fn connect_upstream(
    remote: tokio_btls::SslStream<tokio::net::TcpStream>,
    proxydata: &ConnectionData,
) -> Result<
    (
        Arc<Mutex<UpstreamSend>>,
        http2::client::Connection<tokio_btls::SslStream<tokio::net::TcpStream>, Bytes>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    let upstream_builder = build_upstream_h2_builder(proxydata.http2.clone()).await?;

    let (upstream_send, upstream_conn) = upstream_builder.handshake::<_, Bytes>(remote).await?;

    Ok((Arc::new(Mutex::new(upstream_send)), upstream_conn))
}
