use crate::config::*;
use crate::fingerprint::cert::MitmCa;
use crate::fingerprint::helpers::*;

use btls::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_btls::SslStream;

pub fn create_ssl_acceptor(
    ca: Arc<MitmCa>,
    sni_tx: mpsc::UnboundedSender<String>,
    tls: Arc<TlsConfig>,
) -> Result<SslAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    let alpn = tls.encode_alpn_wire();
    set_alpn_select_callback(&mut builder, alpn);
    set_select_certificate_callback(ca, sni_tx, &mut builder);
    Ok(builder.build())
}

pub async fn create_ssl_acceptor_upstream(
    upstream: TcpStream,
    target_host: &str,
    tls: Arc<TlsConfig>,
    alpn: Option<Vec<u8>>,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_default_verify_paths()?;

    set_cipher_suites(&mut builder, &tls)?;
    set_alpn_protos(&mut builder, alpn)?;
    set_curves_list(&mut builder, &tls)?;
    set_sigalgs_list(&mut builder, &tls)?;
    set_extensions_order(&mut builder, &tls)?;

    let connector = builder.build();

    let ssl = connector.configure()?.into_ssl(target_host)?;
    let mut s = SslStream::new(ssl, upstream)?;
    Pin::new(&mut s).connect().await?;

    Ok(s)
}

pub async fn handle_tls(
    client: TcpStream,
    acceptor: SslAcceptor,
) -> Result<(SslStream<TcpStream>, Option<Vec<u8>>), Box<dyn std::error::Error + Send + Sync>> {
    let ssl = Ssl::new(acceptor.context())?;
    let mut tls_stream = SslStream::new(ssl, client)?;

    if let Err(e) = Pin::new(&mut tls_stream).accept().await {
        eprintln!("[TLS] Handshake Failed: {}", e);
        return Err(e.into());
    }
    let selected_alpn = tls_stream.ssl().selected_alpn_protocol().map(|bytes| {
        let mut wire = Vec::with_capacity(1 + bytes.len());
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(bytes);
        wire
    });
    Ok((tls_stream, selected_alpn))
}
