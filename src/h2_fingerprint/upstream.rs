use crate::config::*;
use crate::h2_fingerprint::h2::ConnectionData;
use crate::proxy;
use crate::tls_fingerprint;
use http2::frame::{Priorities, PseudoOrder, SettingsOrder};
use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_btls::SslStream;

pub async fn build_upstream_h2_builder(
    config: Arc<Http2Config>,
) -> Result<http2::client::Builder, Box<dyn Error + Send + Sync>> {
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

    builder.initial_connection_window_size(config.connection_window_update);

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
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(v) = config.settings.header_table_size {
        builder.header_table_size(v as u32);
    }

    if let Some(v) = config.settings.initial_window_size {
        builder.initial_window_size(v as u32);
    }

    if let Some(v) = config.settings.max_frame_size {
        builder.max_frame_size(v as u32);
    }

    if let Some(v) = config.settings.max_concurrent_streams {
        builder.max_concurrent_streams(v as u32);
    }

    builder.enable_push(config.settings.enable_push);

    if let Some(v) = config.settings.max_header_list_size {
        builder.max_header_list_size(v as u32);
    }

    Ok(())
}

pub async fn upstream_reconnect(
    proxydata: ConnectionData,
) -> Result<SslStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let remote = match proxy::tcp::upstream_connect(&proxydata.packet, proxydata.upstream).await? {
        proxy::tcp::ConnectionStatus::Success(stream) => stream,
        proxy::tcp::ConnectionStatus::Failure(reason) => {
            eprintln!("[TCP] Connection failure: {}", reason);
            return Err(reason.into());
        }
    };

    remote.set_nodelay(true)?;

    let (remote, alpn) =
        tls_fingerprint::tls::create_ssl_acceptor_upstream(remote, &proxydata.sni, proxydata.tls)
            .await?;

    Ok(remote)
}
