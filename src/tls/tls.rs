use crate::tls::cert::MitmCa;
use boring::ssl::{ClientHello, NameType, SelectCertError, SslAcceptor, SslConnector, SslMethod};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_boring::SslStream;

pub fn create_ssl_acceptor(
    ca: Arc<MitmCa>,
    sni_tx: mpsc::UnboundedSender<String>,
) -> Result<SslAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
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
    Ok(builder.build())
}

pub async fn handle_tls(
    client: TcpStream,
    acceptor: SslAcceptor,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let tls_stream = match tokio_boring::accept(&acceptor, client).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("[TLS] Handshake Failed: {}", e);
            return Err(e.into());
        }
    };
    Ok(tls_stream)
}

pub async fn create_ssl_acceptor_upstream(
    upstream: TcpStream,
    target_host: &str,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_default_verify_paths()?;

    let connector = builder.build();
    let ssl_config = connector.configure()?;

    let server_tls_stream = tokio_boring::connect(ssl_config, target_host, upstream).await?;

    Ok(server_tls_stream)
}
