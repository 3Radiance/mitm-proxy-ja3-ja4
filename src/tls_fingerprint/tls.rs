use crate::config::*;
use crate::tls_fingerprint::cert::MitmCa;
use crate::tls_fingerprint::helpers::*;

use btls::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_btls::SslStream;

pub fn create_ssl_acceptor(
    ca: Arc<MitmCa>,
    sni_tx: mpsc::UnboundedSender<String>,
    alpn: &Option<Vec<u8>>,
) -> Result<SslAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

    if let Some(alpn) = alpn {
        set_alpn_select_callback(&mut builder, alpn.clone());
    } else {
        set_alpn_select_callback(&mut builder, b"\x08http/1.1".to_vec());
    }
    set_select_certificate_callback(ca, sni_tx, &mut builder);
    Ok(builder.build())
}

pub async fn create_ssl_acceptor_upstream(
    upstream: TcpStream,
    target_host: &str,
    tls: Arc<TlsConfig>,
) -> Result<(SslStream<TcpStream>, Option<Vec<u8>>), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_default_verify_paths()?;

    set_cipher_suites(&mut builder, tls.clone())?;
    set_alpn_protos(&mut builder, tls.encode_alpn_wire())?;
    set_curves_list(&mut builder, tls.clone())?;
    set_sigalgs_list(&mut builder, tls.clone())?;
    set_record_size_limit(&mut builder, tls.clone());
    set_cert_compression(&mut builder, tls.clone())?;
    set_grease(&mut builder, tls.clone());
    set_extensions_order(&mut builder, tls)?;

    let connector = builder.build();

    let ssl = connector.configure()?.into_ssl(target_host)?;
    let mut s = SslStream::new(ssl, upstream)?;
    Pin::new(&mut s).connect().await?;

    let alpn = s.ssl().selected_alpn_protocol().map(|p| {
        let mut wire = Vec::with_capacity(1 + p.len());
        wire.push(p.len() as u8);
        wire.extend_from_slice(p);
        wire
    });

    Ok((s, alpn))
}

pub async fn handle_tls(
    client: TcpStream,
    acceptor: SslAcceptor,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let ssl = Ssl::new(acceptor.context())?;
    let mut tls_stream = SslStream::new(ssl, client)?;

    if let Err(e) = Pin::new(&mut tls_stream).accept().await {
        eprintln!("[TLS] Handshake Failed: {}", e);
        return Err(e.into());
    }

    Ok(tls_stream)
}
