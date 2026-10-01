use crate::config::*;
use crate::h2_fingerprint::h2::ConnectionData;
use crate::proxy;
use crate::tls_fingerprint;
use anyhow::Result;
use http2::frame::{Priorities, PseudoOrder, SettingsOrder};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_btls::SslStream;

use std::pin::Pin;
use tokio::time::Duration;

pub async fn build_upstream_h2_builder(config: Arc<Http2Config>) -> Result<http2::client::Builder> {
    let mut builder = http2::client::Builder::new();

    let mut pseudo_builder = PseudoOrder::builder();
    let pseudo_headers_order = config.parse_pseudo_headers()?;
    for id in pseudo_headers_order {
        pseudo_builder = pseudo_builder.push(id);
    }
    builder.headers_pseudo_order(pseudo_builder.build());

    let mut settings_builder = SettingsOrder::builder();
    let settings_order = config.parse_settings_order()?;
    for id in settings_order {
        settings_builder = settings_builder.push(id);
    }
    builder.settings_order(settings_builder.build());

    set_settings_frame(&mut builder, config.clone())?;

    if let Some(frames) = &config.priority_frames {
        if !frames.is_empty() {
            let mut priorities_builder = Priorities::builder();
            for frame in config.parse_priority_frames() {
                priorities_builder = priorities_builder.push(frame);
            }
            builder.priorities(priorities_builder.build());
        }
    }

    if let Some(dependency) = config.parse_headers_priority() {
        builder.headers_stream_dependency(dependency);
    }

    if let Some(cwu) = config.connection_window_update {
        builder.initial_connection_window_size(cwu);
    }

    let initial_id = if let Some(explicit) = config.initial_stream_id {
        explicit
    } else {
        match &config.priority_frames {
            Some(frames) if !frames.is_empty() => {
                frames.iter().map(|f| f.stream_id).max().unwrap_or(0) + 2
            }
            _ => 1,
        }
    };
    builder.initial_stream_id(initial_id);

    Ok(builder)
}

pub fn set_settings_frame(
    builder: &mut http2::client::Builder,
    config: Arc<Http2Config>,
) -> Result<()> {
    if let Some(settings) = &config.settings {
        if let Some(v) = settings.header_table_size {
            builder.header_table_size(v as u32);
        }

        if let Some(v) = settings.initial_window_size {
            builder.initial_window_size(v as u32);
        }

        if let Some(v) = settings.max_frame_size {
            builder.max_frame_size(v as u32);
        }

        if let Some(v) = settings.max_concurrent_streams {
            builder.max_concurrent_streams(v as u32);
        }

        builder.enable_push(settings.enable_push);

        if let Some(v) = settings.max_header_list_size {
            builder.max_header_list_size(v as u32);
        }
    }

    Ok(())
}

pub async fn upstream_reconnect(proxydata: ConnectionData) -> Result<SslStream<TcpStream>> {
    let host = match proxydata.packet.get_header("host") {
        Some(h) => h,
        None => {
            return Err(anyhow::anyhow!("Host header not found".to_string(),));
        }
    };

    let remote =
        match proxy::tcp::upstream_connect(host, proxydata.upstream.clone(), proxydata.tcp.clone())
            .await?
        {
            proxy::tcp::ConnectionStatus::Success(stream) => stream,
            proxy::tcp::ConnectionStatus::Failure(reason) => {
                crate::log_tag!(warn, "TCP", "Connection failure: {}", reason);
                return Err(anyhow::anyhow!(reason));
            }
        };

    remote.set_nodelay(true)?;

    let remote_ssl =
        tls_fingerprint::tls::create_ssl_acceptor_upstream(proxydata.tls.clone()).await?;

    let mut ssl = remote_ssl.configure()?.into_ssl(&proxydata.sni)?;

    tls_fingerprint::helpers::set_alps(&mut ssl, proxydata.http2.clone(), proxydata.tls.clone());
    tls_fingerprint::ech::set_ech(
        &mut ssl,
        proxydata.tls.clone(),
        proxydata.tcp.clone(),
        proxydata.http2.clone(),
        &*proxydata.sni,
        proxydata.upstream.clone(),
        proxydata.cache.clone(),
    )
    .await?;

    let mut remote = SslStream::new(ssl, remote)?;

    tokio::time::timeout(Duration::from_secs(5), Pin::new(&mut remote).connect()).await??;

    let alpn = remote.ssl().selected_alpn_protocol().map(|p| {
        let mut wire = Vec::with_capacity(1 + p.len());
        wire.push(p.len() as u8);
        wire.extend_from_slice(p);
        wire
    });

    if let Some(selected_alpn) = &*proxydata.selected_alpn {
        if let Some(alpn) = alpn {
            if selected_alpn != &alpn {
                return Err(anyhow::anyhow!(
                    "ALPN mismatch on reconnect: expected {:?}, got {:?}",
                    selected_alpn,
                    alpn
                ));
            }
        }
    }

    Ok(remote)
}
