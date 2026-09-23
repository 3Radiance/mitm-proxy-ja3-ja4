use crate::config::*;
use crate::tls::cert::MitmCa;

use btls::ssl::{
    select_next_proto, AlpnError, ClientHello, NameType, SelectCertError, Ssl, SslAcceptor,
    SslConnector, SslContextBuilder, SslMethod,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_btls::SslStream;

pub fn create_ssl_acceptor(
    ca: Arc<MitmCa>,
    sni_tx: mpsc::UnboundedSender<String>,
) -> Result<SslAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    set_cert(ca, sni_tx, &mut builder);
    Ok(builder.build())
}
pub async fn create_ssl_acceptor_upstream(
    upstream: TcpStream,
    target_host: &str,
    tls: Arc<TlsConfig>,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_default_verify_paths()?;
    set_cipher_suites(&mut builder, &tls)?;

    let connector = builder.build();

    let ssl = connector.configure()?.into_ssl(target_host)?;
    let mut s = SslStream::new(ssl, upstream)?;
    Pin::new(&mut s).connect().await?;

    Ok(s)
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

fn set_cert(
    ca: Arc<MitmCa>,
    sni_tx: mpsc::UnboundedSender<String>,
    builder: &mut SslContextBuilder,
) {
    builder.set_select_certificate_callback(move |mut client_hello: ClientHello<'_>| {
        let ssl = client_hello.ssl_mut();
        let domain = match ssl.servername(NameType::HOST_NAME) {
            Some(d) => d,
            None => {
                return Err(SelectCertError::ERROR);
            }
        };

        let _ = sni_tx.send(domain.to_string());

        match ca.get_or_issue_cert(domain) {
            Ok((x509, pkey)) => {
                if ssl.set_certificate(&x509).is_err() || ssl.set_private_key(&pkey).is_err() {
                    return Err(SelectCertError::ERROR);
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("[TLS] Failed to issue cert for {}: {}", domain, e);
                Err(SelectCertError::ERROR)
            }
        }
    });
}

fn set_cipher_suites(
    builder: &mut SslContextBuilder,
    tls: &TlsConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    builder.set_preserve_tls13_cipher_list(true);

    let ciphers = tls.cipher_suites.join(":");

    builder
        .set_strict_cipher_list(&ciphers)
        .map_err(|e| format!("[TLS] Failed to set cipher list: {e}"))?;

    Ok(())
}
