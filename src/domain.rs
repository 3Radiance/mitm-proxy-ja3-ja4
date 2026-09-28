use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

use crate::config::{
    Config, H2HeadersPriority, H2PriorityFrame, Http1Config, Http2Config, ProfileConfig, Settings,
    TcpConfig, TlsConfig,
};

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default, deserialize_with = "present_as_override")]
    pub upstream_proxy: Option<Option<String>>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialTcpConfig {
    #[serde(default)]
    pub ttl: Option<u8>,
    #[serde(default)]
    pub window_size: Option<u32>,
    #[serde(default)]
    pub mss: Option<u16>,
    #[serde(default)]
    pub window_scale: Option<u8>,
    #[serde(default)]
    pub dont_fragment: Option<bool>,
    #[serde(default)]
    pub tcp_options_order: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialTlsConfig {
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub curves: Option<Vec<String>>,
    #[serde(default)]
    pub signature_algorithms: Option<Vec<String>>,
    #[serde(default)]
    pub extensions_order: Option<Vec<String>>,
    #[serde(default)]
    pub cert_compression: Option<Vec<String>>,
    #[serde(default)]
    pub permute_extensions: Option<bool>,
    #[serde(default)]
    pub status_request: Option<bool>,
    #[serde(default)]
    pub signed_certificate_timestamp: Option<bool>,
    #[serde(default)]
    pub alps: Option<bool>,
    #[serde(default)]
    pub session_ticket: Option<bool>,
    #[serde(default)]
    pub grease_enabled: Option<bool>,
    #[serde(default)]
    pub enable_ech: Option<bool>,
    #[serde(default)]
    pub enable_ech_grease: Option<bool>,
    #[serde(default)]
    pub record_size_limit: Option<u16>,
    #[serde(default)]
    pub doh: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialSettings {
    #[serde(default)]
    pub header_table_size: Option<u32>,
    #[serde(default)]
    pub enable_push: Option<bool>,
    #[serde(default)]
    pub max_concurrent_streams: Option<u32>,
    #[serde(default)]
    pub initial_window_size: Option<u32>,
    #[serde(default)]
    pub max_frame_size: Option<u32>,
    #[serde(default)]
    pub max_header_list_size: Option<u32>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialHttp2Config {
    #[serde(default)]
    pub settings: PartialSettings,
    #[serde(default)]
    pub settings_order: Option<Vec<String>>,
    #[serde(default)]
    pub connection_window_update: Option<u32>,
    #[serde(default)]
    pub initial_stream_id: Option<u32>,
    #[serde(default)]
    pub priority_frames: Option<Vec<H2PriorityFrame>>,
    #[serde(default)]
    pub headers_priority: Option<H2HeadersPriority>,
    #[serde(default)]
    pub end_stream_on_headers: Option<bool>,
    #[serde(default)]
    pub pseudo_headers_order: Option<Vec<String>>,
    #[serde(default)]
    pub headers_order: Option<Vec<String>>,
    #[serde(default)]
    pub http_headers: Option<HashMap<String, Option<String>>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialHttp1Config {
    #[serde(default)]
    pub headers_order: Option<Vec<String>>,
    #[serde(default)]
    pub http_headers: Option<HashMap<String, Option<String>>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct DomainOverlay {
    #[serde(default)]
    pub config: PartialConfig,
    #[serde(default)]
    pub tcp: PartialTcpConfig,
    #[serde(default)]
    pub tls: PartialTlsConfig,
    #[serde(default)]
    pub http2: PartialHttp2Config,
    #[serde(default)]
    pub http1: PartialHttp1Config,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct DomainConfig {
    #[serde(flatten)]
    pub overlays: HashMap<String, DomainOverlay>,
}

impl DomainConfig {
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }
}

impl PartialConfig {
    pub fn merge_into(&self, base: &Config) -> Config {
        Config {
            port: self.port.unwrap_or(base.port),
            upstream_proxy: self
                .upstream_proxy
                .clone()
                .unwrap_or_else(|| base.upstream_proxy.clone()),
            cert: self.cert.clone().unwrap_or_else(|| base.cert.clone()),
            key: self.key.clone().unwrap_or_else(|| base.key.clone()),
        }
    }
}

impl PartialTcpConfig {
    pub fn merge_into(&self, base: &TcpConfig) -> TcpConfig {
        TcpConfig {
            ttl: self.ttl.unwrap_or(base.ttl),
            window_size: self.window_size.unwrap_or(base.window_size),
            mss: self.mss.unwrap_or(base.mss),
            window_scale: self.window_scale.unwrap_or(base.window_scale),
            dont_fragment: self.dont_fragment.unwrap_or(base.dont_fragment),
            tcp_options_order: self
                .tcp_options_order
                .clone()
                .unwrap_or_else(|| base.tcp_options_order.clone()),
        }
    }
}

impl PartialTlsConfig {
    pub fn merge_into(&self, base: &TlsConfig) -> TlsConfig {
        TlsConfig {
            cipher_suites: self
                .cipher_suites
                .clone()
                .unwrap_or_else(|| base.cipher_suites.clone()),
            alpn: self.alpn.clone().unwrap_or_else(|| base.alpn.clone()),
            curves: self.curves.clone().unwrap_or_else(|| base.curves.clone()),
            signature_algorithms: self
                .signature_algorithms
                .clone()
                .unwrap_or_else(|| base.signature_algorithms.clone()),
            extensions_order: self
                .extensions_order
                .clone()
                .or_else(|| base.extensions_order.clone()),
            cert_compression: self
                .cert_compression
                .clone()
                .unwrap_or_else(|| base.cert_compression.clone()),
            permute_extensions: self
                .permute_extensions
                .unwrap_or(base.permute_extensions),
            status_request: self.status_request.unwrap_or(base.status_request),
            signed_certificate_timestamp: self
                .signed_certificate_timestamp
                .unwrap_or(base.signed_certificate_timestamp),
            alps: self.alps.unwrap_or(base.alps),
            session_ticket: self.session_ticket.unwrap_or(base.session_ticket),
            grease_enabled: self.grease_enabled.unwrap_or(base.grease_enabled),
            enable_ech: self.enable_ech.unwrap_or(base.enable_ech),
            enable_ech_grease: self
                .enable_ech_grease
                .unwrap_or(base.enable_ech_grease),
            record_size_limit: self
                .record_size_limit
                .or(base.record_size_limit),
            doh: self.doh.clone().unwrap_or_else(|| base.doh.clone()),
        }
    }
}

impl PartialSettings {
    pub fn merge_into(&self, base: &Settings) -> Settings {
        Settings {
            header_table_size: self.header_table_size.or(base.header_table_size),
            enable_push: self.enable_push.unwrap_or(base.enable_push),
            max_concurrent_streams: self
                .max_concurrent_streams
                .or(base.max_concurrent_streams),
            initial_window_size: self.initial_window_size.or(base.initial_window_size),
            max_frame_size: self.max_frame_size.or(base.max_frame_size),
            max_header_list_size: self
                .max_header_list_size
                .or(base.max_header_list_size),
        }
    }
}

impl PartialHttp2Config {
    pub fn merge_into(&self, base: &Http2Config) -> Http2Config {
        Http2Config {
            settings: self.settings.merge_into(&base.settings),
            settings_order: self
                .settings_order
                .clone()
                .unwrap_or_else(|| base.settings_order.clone()),
            connection_window_update: self
                .connection_window_update
                .unwrap_or(base.connection_window_update),
            initial_stream_id: self.initial_stream_id.or(base.initial_stream_id),
            priority_frames: self
                .priority_frames
                .clone()
                .or_else(|| base.priority_frames.clone()),
            headers_priority: self
                .headers_priority
                .clone()
                .or_else(|| base.headers_priority.clone()),
            end_stream_on_headers: self
                .end_stream_on_headers
                .unwrap_or(base.end_stream_on_headers),
            pseudo_headers_order: self
                .pseudo_headers_order
                .clone()
                .unwrap_or_else(|| base.pseudo_headers_order.clone()),
            headers_order: self
                .headers_order
                .clone()
                .or_else(|| base.headers_order.clone()),
            http_headers: self
                .http_headers
                .clone()
                .or_else(|| base.http_headers.clone()),
        }
    }
}

impl PartialHttp1Config {
    pub fn merge_into(&self, base: &Http1Config) -> Http1Config {
        Http1Config {
            headers_order: self
                .headers_order
                .clone()
                .or_else(|| base.headers_order.clone()),
            http_headers: self
                .http_headers
                .clone()
                .or_else(|| base.http_headers.clone()),
        }
    }
}

impl DomainOverlay {
    pub fn merge_into(&self, base: &ProfileConfig) -> ProfileConfig {
        ProfileConfig {
            config: self.config.merge_into(&base.config),
            tcp: self.tcp.merge_into(&base.tcp),
            tls: self.tls.merge_into(&base.tls),
            http2: self.http2.merge_into(&base.http2),
            http1: self.http1.merge_into(&base.http1),
        }
    }
}

fn present_as_override<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(Some(opt.filter(|s| !s.trim().is_empty())))
}
