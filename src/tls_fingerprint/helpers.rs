use crate::config::*;
use crate::tls_fingerprint::cert::MitmCa;
use crate::tls_fingerprint::compression::{BrotliCompressor, ZlibCompressor, ZstdCompressor};

use btls::ssl::{AlpnError, ClientHello, NameType, SelectCertError, SslContextBuilder, SslOptions};

use std::sync::Arc;

pub fn set_select_certificate_callback(ca: Arc<MitmCa>, builder: &mut SslContextBuilder) {
    builder.set_select_certificate_callback(move |mut client_hello: ClientHello<'_>| {
        let ssl = client_hello.ssl_mut();
        let domain = match ssl.servername(NameType::HOST_NAME) {
            Some(d) => d,
            None => {
                return Err(SelectCertError::ERROR);
            }
        };

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

pub fn set_cipher_suites(
    builder: &mut SslContextBuilder,
    tls: Arc<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    builder.set_preserve_tls13_cipher_list(true);

    let ciphers = tls.cipher_suites.join(":");

    builder
        .set_cipher_list(&ciphers)
        .map_err(|e| format!("[TLS] Failed to set cipher list: {e}"))?;

    Ok(())
}

pub fn set_alpn_protos(
    builder: &mut SslContextBuilder,
    alpn_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    builder
        .set_alpn_protos(&alpn_bytes)
        .map_err(|e| format!("[TLS] Failed to set ALPN: {e}"))?;
    Ok(())
}

pub fn set_curves_list(
    builder: &mut SslContextBuilder,
    tls: Arc<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let curve_list = tls.curves.join(":");
    builder
        .set_curves_list(&curve_list)
        .map_err(|e| format!("[TLS] Failed to set curves: {e}"))?;
    Ok(())
}

pub fn set_sigalgs_list(
    builder: &mut SslContextBuilder,
    tls: Arc<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sigalgs = tls.signature_algorithms.join(":");
    builder
        .set_sigalgs_list(&sigalgs)
        .map_err(|e| format!("[TLS] Failed to set signature algorithms: {e}"))?;
    Ok(())
}

pub fn set_extensions_order(
    builder: &mut SslContextBuilder,
    tls: Arc<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ext) = tls.parse_extension()? {
        builder
            .set_extension_permutation(&ext)
            .map_err(|e| format!("[TLS] Failed to set extension order: {e}"))?;
    }

    Ok(())
}

pub fn set_record_size_limit(builder: &mut SslContextBuilder, tls: Arc<TlsConfig>) {
    if let Some(limit) = tls.record_size_limit {
        builder.set_record_size_limit(limit);
    }
}

pub fn set_cert_compression(
    builder: &mut SslContextBuilder,
    tls: Arc<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for algo in &tls.cert_compression {
        match algo.as_str() {
            "brotli" => builder
                .add_certificate_compression_algorithm(BrotliCompressor)
                .map_err(|e| format!("[TLS] Failed to add brotli compression: {e}"))?,
            "zlib" => builder
                .add_certificate_compression_algorithm(ZlibCompressor)
                .map_err(|e| format!("[TLS] Failed to add zlib compression: {e}"))?,
            "zstd" => builder
                .add_certificate_compression_algorithm(ZstdCompressor)
                .map_err(|e| format!("[TLS] Failed to add zstd compression: {e}"))?,
            other => {
                return Err(format!("[TLS] Unknown cert compression algorithm: {other}").into())
            }
        }
    }
    Ok(())
}

pub fn set_grease(builder: &mut SslContextBuilder, tls: Arc<TlsConfig>) {
    builder.set_grease_enabled(tls.grease_enabled);
}

pub fn set_permute_extensions(builder: &mut SslContextBuilder, tls: Arc<TlsConfig>) {
    builder.set_permute_extensions(tls.permute_extensions);
}

pub fn set_status_request(builder: &mut SslContextBuilder, tls: Arc<TlsConfig>) {
    if tls.status_request {
        builder.enable_ocsp_stapling();
    }
}

pub fn set_signed_certificate_timestamp(builder: &mut SslContextBuilder, tls: Arc<TlsConfig>) {
    if tls.signed_certificate_timestamp {
        builder.enable_signed_cert_timestamps();
    }
}

pub fn set_session_ticket(builder: &mut SslContextBuilder, tls: Arc<TlsConfig>) {
    if tls.session_ticket {
        builder.clear_options(SslOptions::NO_TICKET);
    } else {
        builder.set_options(SslOptions::NO_TICKET);
    }
}
