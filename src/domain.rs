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
    #[serde(default, deserialize_with = "deserialize_some_hex_or_int")]
    pub mark: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub ttl: Option<Option<u8>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub window_size: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub mss: Option<Option<u16>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub window_scale: Option<Option<u8>>,
    #[serde(default)]
    pub dont_fragment: Option<bool>,
    #[serde(default)]
    pub timestamp: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub tcp_options_order: Option<Option<Vec<String>>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialTlsConfig {
    #[serde(default, deserialize_with = "deserialize_some")]
    pub cipher_suites: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub alpn: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub curves: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub signature_algorithms: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub extensions_order: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub cert_compression: Option<Option<Vec<String>>>,
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
    #[serde(default, deserialize_with = "deserialize_some")]
    pub delegated_credentials: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub record_size_limit: Option<Option<u16>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub doh: Option<Option<Vec<String>>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialSettings {
    #[serde(default, deserialize_with = "deserialize_some")]
    pub header_table_size: Option<Option<u32>>,
    #[serde(default)]
    pub enable_push: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub max_concurrent_streams: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub initial_window_size: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub max_frame_size: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub max_header_list_size: Option<Option<u32>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialHttp2Config {
    #[serde(default)]
    pub settings: Option<PartialSettings>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub settings_order: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub connection_window_update: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub initial_stream_id: Option<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub priority_frames: Option<Option<Vec<H2PriorityFrame>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub headers_priority: Option<Option<H2HeadersPriority>>,
    #[serde(default)]
    pub end_stream_on_headers: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub pseudo_headers_order: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub headers_order: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub http_headers: Option<Option<HashMap<String, Option<String>>>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct PartialHttp1Config {
    #[serde(default, deserialize_with = "deserialize_some")]
    pub headers_order: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub http_headers: Option<Option<HashMap<String, Option<String>>>>,
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
            mark: self.mark.unwrap_or(base.mark),
            qnum_syn: base.qnum_syn,
            qnum_tcp: base.qnum_tcp,
            auto_iptables: base.auto_iptables,
            ttl: self.ttl.unwrap_or(base.ttl),
            window_size: self.window_size.unwrap_or(base.window_size),
            mss: self.mss.unwrap_or(base.mss),
            window_scale: self.window_scale.unwrap_or(base.window_scale),
            dont_fragment: self.dont_fragment.unwrap_or(base.dont_fragment),
            timestamp: self.timestamp.unwrap_or(base.timestamp),
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
                .unwrap_or_else(|| base.extensions_order.clone()),
            cert_compression: self
                .cert_compression
                .clone()
                .unwrap_or_else(|| base.cert_compression.clone()),
            permute_extensions: self.permute_extensions.unwrap_or(base.permute_extensions),
            status_request: self.status_request.unwrap_or(base.status_request),
            signed_certificate_timestamp: self
                .signed_certificate_timestamp
                .unwrap_or(base.signed_certificate_timestamp),
            alps: self.alps.unwrap_or(base.alps),
            session_ticket: self.session_ticket.unwrap_or(base.session_ticket),
            grease_enabled: self.grease_enabled.unwrap_or(base.grease_enabled),
            enable_ech: self.enable_ech.unwrap_or(base.enable_ech),
            enable_ech_grease: self.enable_ech_grease.unwrap_or(base.enable_ech_grease),
            delegated_credentials: self
                .delegated_credentials
                .clone()
                .unwrap_or_else(|| base.delegated_credentials.clone()),
            record_size_limit: self.record_size_limit.unwrap_or(base.record_size_limit),
            doh: self.doh.clone().unwrap_or_else(|| base.doh.clone()),
        }
    }
}

impl PartialSettings {
    pub fn merge_into(&self, base: &Settings) -> Settings {
        Settings {
            header_table_size: self.header_table_size.unwrap_or(base.header_table_size),
            enable_push: self.enable_push.unwrap_or(base.enable_push),
            max_concurrent_streams: self
                .max_concurrent_streams
                .unwrap_or(base.max_concurrent_streams),
            initial_window_size: self.initial_window_size.unwrap_or(base.initial_window_size),
            max_frame_size: self.max_frame_size.unwrap_or(base.max_frame_size),
            max_header_list_size: self
                .max_header_list_size
                .unwrap_or(base.max_header_list_size),
        }
    }
}

impl PartialHttp2Config {
    pub fn merge_into(&self, base: &Http2Config) -> Http2Config {
        Http2Config {
            settings: self
                .settings
                .as_ref()
                .and_then(|s| base.settings.as_ref().map(|b| s.merge_into(b)))
                .or_else(|| base.settings.clone()),
            settings_order: self
                .settings_order
                .clone()
                .unwrap_or_else(|| base.settings_order.clone()),
            connection_window_update: self
                .connection_window_update
                .unwrap_or(base.connection_window_update),
            initial_stream_id: self.initial_stream_id.unwrap_or(base.initial_stream_id),
            priority_frames: self
                .priority_frames
                .clone()
                .unwrap_or_else(|| base.priority_frames.clone()),
            headers_priority: self
                .headers_priority
                .clone()
                .unwrap_or_else(|| base.headers_priority.clone()),
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
                .unwrap_or_else(|| base.headers_order.clone()),
            http_headers: self
                .http_headers
                .clone()
                .unwrap_or_else(|| base.http_headers.clone()),
        }
    }
}

impl PartialHttp1Config {
    pub fn merge_into(&self, base: &Http1Config) -> Http1Config {
        Http1Config {
            headers_order: self
                .headers_order
                .clone()
                .unwrap_or_else(|| base.headers_order.clone()),
            http_headers: self
                .http_headers
                .clone()
                .unwrap_or_else(|| base.http_headers.clone()),
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

fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

fn deserialize_some_hex_or_int<'de, D>(deserializer: D) -> Result<Option<Option<u32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::config::parse_opt_hex_or_int(deserializer).map(Some)
}
