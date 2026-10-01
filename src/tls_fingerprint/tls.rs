use crate::config::*;
use crate::tls_fingerprint::cert::MitmCa;
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

pub async fn create_ssl_acceptor_upstream(tls: Arc<TlsConfig>) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    let mut store_builder = btls::x509::store::X509StoreBuilder::new()?;

    for cert_der in chromium_roots::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = btls::x509::X509::from_der(cert_der) {
            store_builder.add_cert(cert)?;
        }
    }

    let store = store_builder.build();
    builder.set_cert_store(store);

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
    set_delegated_credentials(&mut builder, tls.clone())?;
    set_extensions_order(&mut builder, tls.clone())?;

    let connector = builder.build();

    Ok(connector)
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
