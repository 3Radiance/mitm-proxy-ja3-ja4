use crate::config::*;
use crate::tls::cert::MitmCa;

use btls::ssl::{AlpnError, ClientHello, NameType, SelectCertError, SslContextBuilder};

use std::sync::Arc;
use tokio::sync::mpsc;

pub fn set_select_certificate_callback(
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

pub fn set_cipher_suites(
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

pub fn set_alpn_protos(
    builder: &mut SslContextBuilder,
    alpn_bytes: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(alpn) = alpn_bytes {
        builder
            .set_alpn_protos(&alpn)
            .map_err(|e| format!("[TLS] Failed to set ALPN: {e}"))?;
    }
    Ok(())
}

pub fn set_alpn_select_callback(builder: &mut SslContextBuilder, alpn_bytes: Vec<u8>) {
    builder.set_alpn_select_callback(move |_ssl, client_protos| {
        let mut client_cursor = client_protos;

        while !client_cursor.is_empty() {
            let len = client_cursor[0] as usize;
            if client_cursor.len() < 1 + len {
                break;
            }
            let client_proto = &client_cursor[1..1 + len];

            let mut server_cursor = &alpn_bytes[..];
            while !server_cursor.is_empty() {
                let s_len = server_cursor[0] as usize;
                let server_proto = &server_cursor[1..1 + s_len];

                if client_proto == server_proto {
                    return Ok(client_proto);
                }
                server_cursor = &server_cursor[1 + s_len..];
            }

            client_cursor = &client_cursor[1 + len..];
        }

        Err(AlpnError::NOACK)
    });
}
