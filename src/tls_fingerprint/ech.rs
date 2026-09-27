use anyhow::{anyhow, Context, Result};
use tokio::net::TcpStream;
use tokio_btls::SslStream;

use crate::{
    config::{Http2Config, TlsConfig},
    h2_fingerprint::upstream::build_upstream_h2_builder,
    proxy::tcp::{upstream_connect, ConnectionStatus},
    tls_fingerprint,
};
use btls::ssl::Ssl;
use rand::seq::SliceRandom;
use std::sync::Arc;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_proto::rr::{Name, RData, RecordType};

use bytes::Bytes;

use moka::future::Cache;

#[derive(Clone)]
pub struct EchCache {
    pub cache: Cache<String, Option<Vec<u8>>>,
}

pub async fn set_ech(
    ssl: &mut Ssl,
    tls: Arc<TlsConfig>,
    http2: Arc<Http2Config>,
    target_domain: &str,
    upstream: Arc<Option<String>>,
    cache: Arc<EchCache>,
) -> Result<()> {
    if !tls.enable_ech {
        if tls.enable_ech_grease {
            ssl.set_enable_ech_grease(true);
        }
        return Ok(());
    }
    if let Some(ech_config) = cache.cache.get(target_domain).await {
        crate::log_tag!(debug, "ECH", "CACHE HIT: {}", target_domain);
        if let Some(config) = ech_config {
            ssl.set_ech_config_list(&config)?;
        } else if tls.enable_ech_grease {
            ssl.set_enable_ech_grease(true);
        }

        return Ok(());
    }
    let doh_domain: &str = {
        let mut rng = rand::thread_rng();
        tls.doh
            .choose(&mut rng)
            .map(String::as_str)
            .context("Failed to get DoH domain")?
    };

    let remote = upstream_for_ech(
        tls.clone(),
        http2.clone(),
        upstream,
        cache.clone(),
        doh_domain,
    )
    .await?;

    let upstream_builder = build_upstream_h2_builder(http2).await?;
    let (doh_send, doh_conn) = upstream_builder.handshake::<_, Bytes>(remote).await?;

    tokio::spawn(async move {
        let _ = doh_conn.await;
    });

    let query_bytes = build_msg(target_domain)?;

    let mut send_request = doh_send.ready().await?;

    let req = build_req(target_domain)?;

    let (response, mut req_body) = send_request.send_request(req, false)?;
    req_body.send_data(bytes::Bytes::from(query_bytes), true)?;

    let response = response.await?;

    let (head, mut body) = response.into_parts();

    if !head.status.is_success() {
        return Err(anyhow!("DoH server returned status {}", head.status));
    }

    let mut resp_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        resp_bytes.extend_from_slice(&chunk?);
    }

    let ech_config = extract_ech_config(&resp_bytes);

    match ech_config {
        Some(config) => {
            ssl.set_ech_config_list(&config)?;
            cache
                .cache
                .insert(target_domain.to_string(), Some(config))
                .await;
        }
        None => {
            if tls.enable_ech_grease {
                ssl.set_enable_ech_grease(true);
            }
            cache.cache.insert(target_domain.to_string(), None).await;
        }
    }

    Ok(())
}

fn extract_ech_config(response_bytes: &[u8]) -> Option<Vec<u8>> {
    let msg = Message::from_vec(response_bytes).ok()?;

    for record in msg.answers.iter() {
        if record.record_type() != RecordType::HTTPS {
            continue;
        }

        if let RData::HTTPS(svcb) = &record.data {
            for (key, value) in &svcb.svc_params {
                if *key != SvcParamKey::EchConfigList {
                    continue;
                }

                if let SvcParamValue::EchConfigList(config) = value {
                    return Some(config.0.to_vec());
                }
            }
        }
    }

    None
}

async fn upstream_for_ech(
    tls: Arc<TlsConfig>,
    http2: Arc<Http2Config>,
    upstream: Arc<Option<String>>,
    cache: Arc<EchCache>,
    doh_domain: &str,
) -> Result<SslStream<TcpStream>> {
    let doh_domain_with_port = format!("{}:443", doh_domain);

    let remote = match upstream_connect(doh_domain_with_port.as_str(), upstream.clone()).await? {
        ConnectionStatus::Success(stream) => stream,
        ConnectionStatus::Failure(reason) => {
            return Err(anyhow::anyhow!("[TCP] Connection failure: {}", reason));
        }
    };

    remote.set_nodelay(true)?;

    let (remote, selected_alpn) = Box::pin(tls_fingerprint::tls::create_ssl_acceptor_upstream(
        remote,
        doh_domain,
        tls.clone(),
        http2.clone(),
        false,
        upstream,
        cache.clone(),
    ))
    .await?;

    if selected_alpn.as_deref() != Some(b"\x02h2") {
        return Err(anyhow!("DoH resolver did not negotiate h2"));
    }

    Ok(remote)
}

fn build_msg(target_domain: &str) -> Result<Vec<u8>> {
    let mut msg = Message::query();
    msg.metadata.recursion_desired = true;

    let name = Name::from_ascii(target_domain)?;
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::HTTPS);
    msg.add_query(query);

    Ok(msg.to_vec()?)
}

fn build_req(doh_domain: &str) -> Result<http::Request<()>> {
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(doh_domain)
        .path_and_query("/dns-query")
        .build()?;

    let req = http::Request::builder()
        .method("POST")
        .uri(&uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(())?;

    Ok(req)
}
