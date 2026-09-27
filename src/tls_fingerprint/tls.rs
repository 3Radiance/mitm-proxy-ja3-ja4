use crate::config::*;
use crate::tls_fingerprint::cert::MitmCa;
use crate::tls_fingerprint::ech::{set_ech, EchCache};
use crate::tls_fingerprint::helpers::*;
use anyhow::Result;

use btls::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio_btls::SslStream;

pub fn create_ssl_acceptor(ca: Arc<MitmCa>, alpn: &Option<Vec<u8>>) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

    if let Some(alpn) = alpn {
        set_alpn_select_callback(&mut builder, alpn.clone());
    } else {
        set_alpn_select_callback(&mut builder, b"\x08http/1.1".to_vec());
    }
    set_select_certificate_callback(ca, &mut builder);
    Ok(builder.build())
}

pub async fn create_ssl_acceptor_upstream(
    client: TcpStream,
    target_host: &str,
    tls: Arc<TlsConfig>,
    http2: Arc<Http2Config>,
    need_ech: bool,
    upstream: Arc<Option<String>>,
    cache: Arc<EchCache>,
) -> Result<(SslStream<TcpStream>, Option<Vec<u8>>)> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_default_verify_paths()?;

    set_cipher_suites(&mut builder, tls.clone())?;
    set_alpn_protos(&mut builder, tls.encode_alpn_wire())?;
    set_curves_list(&mut builder, tls.clone())?;
    set_sigalgs_list(&mut builder, tls.clone())?;
    set_record_size_limit(&mut builder, tls.clone());
    set_cert_compression(&mut builder, tls.clone())?;
    set_grease(&mut builder, tls.clone());
    set_permute_extensions(&mut builder, tls.clone());
    set_status_request(&mut builder, tls.clone());
    set_signed_certificate_timestamp(&mut builder, tls.clone());
    set_session_ticket(&mut builder, tls.clone());
    set_extensions_order(&mut builder, tls.clone())?;

    let connector = builder.build();

    let mut ssl = connector.configure()?.into_ssl(target_host)?;

    set_alps(&mut ssl, http2.clone(), tls.clone());
    if need_ech {
        set_ech(&mut ssl, tls.clone(), http2, target_host, upstream, cache).await?;
    }

    let mut s = SslStream::new(ssl, client)?;

    tokio::time::timeout(Duration::from_secs(5), Pin::new(&mut s).connect()).await??;

    let alpn = s.ssl().selected_alpn_protocol().map(|p| {
        let mut wire = Vec::with_capacity(1 + p.len());
        wire.push(p.len() as u8);
        wire.extend_from_slice(p);
        wire
    });

    let alpn_debug = alpn
        .as_deref()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_else(|| "<none>".to_string());

    crate::log_tag!(
        info,
        "TLS",
        "Upstream TLS handshake completed for {} with ALPN: {}",
        target_host,
        alpn_debug
    );

    Ok((s, alpn))
}

pub async fn handle_tls(client: TcpStream, acceptor: SslAcceptor) -> Result<SslStream<TcpStream>> {
    let ssl = Ssl::new(acceptor.context())?;
    let mut tls_stream = SslStream::new(ssl, client)?;

    if let Err(e) =
        tokio::time::timeout(Duration::from_secs(5), Pin::new(&mut tls_stream).accept()).await?
    {
        crate::log_tag!(error, "TLS", "Handshake failed: {}", e);
        return Err(e.into());
    }

    Ok(tls_stream)
}
