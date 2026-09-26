use anyhow::Result;
use btls::ssl::ExtensionType;
use http2::frame::{Priority, StreamDependency};
use http2::frame::{PseudoId};
use http2::frame::{SettingId};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct AppConfig {
    #[serde(flatten)]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct ProfileConfig {
    pub config: Config,
    pub tcp: TcpConfig,
    pub tls: TlsConfig,
    pub http2: Http2Config,
    pub http1: Http1Config,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub upstream_proxy: Option<String>,
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct TcpConfig {
    pub ttl: u8,
    pub window_size: u32,
    pub mss: u16,
    pub window_scale: u8,
    #[serde(default)]
    pub dont_fragment: bool,
    pub tcp_options_order: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct TlsConfig {
    pub cipher_suites: Vec<String>,
    pub alpn: Vec<String>,
    pub curves: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub extensions_order: Option<Vec<String>>,
    pub cert_compression: Vec<String>,
    pub permute_extensions: bool,
    pub status_request: bool,
    pub signed_certificate_timestamp: bool,
    pub alps: bool,
    pub session_ticket: bool,
    pub grease_enabled: bool,
    pub enable_ech: bool,
    #[serde(default)]
    pub record_size_limit: Option<u16>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Http2Config {
    pub settings: Settings,
    pub settings_order: Vec<String>,
    pub connection_window_update: u32,
    #[serde(default)]
    pub initial_stream_id: Option<u32>,
    #[serde(default)]
    pub priority_frames: Option<Vec<H2PriorityFrame>>,
    #[serde(default)]
    pub headers_priority: Option<H2HeadersPriority>,
    pub end_stream_on_headers: bool,
    pub pseudo_headers_order: Vec<String>,
    pub headers_order: Option<Vec<String>>,
    pub http_headers: Option<HashMap<String, Option<String>>>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Http1Config {
    pub headers_order: Option<Vec<String>>,
    pub http_headers: Option<HashMap<String, Option<String>>>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct H2PriorityFrame {
    pub stream_id: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct H2HeadersPriority {
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub header_table_size: Option<u32>,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
}

impl AppConfig {
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }
}

impl TlsConfig {
    pub fn encode_alpn_wire(&self) -> Vec<u8> {
        let total_len: usize = self.alpn.iter().map(|p| 1 + p.len()).sum();
        let mut bytes = Vec::with_capacity(total_len);

        for proto in &self.alpn {
            let len = proto.len();
            if len > 0 && len <= 255 {
                bytes.push(len as u8);
                bytes.extend_from_slice(proto.as_bytes());
            }
        }
        bytes
    }

    pub fn parse_extension(&self) -> anyhow::Result<Option<Vec<ExtensionType>>> {
        self.extensions_order
            .as_ref()
            .map(|extensions| {
                extensions
                    .iter()
                    .map(|s| match s.as_str() {
                        "server_name" => Ok(ExtensionType::SERVER_NAME),
                        "status_request" => Ok(ExtensionType::STATUS_REQUEST),
                        "supported_groups" => Ok(ExtensionType::SUPPORTED_GROUPS),
                        "ec_point_formats" => Ok(ExtensionType::EC_POINT_FORMATS),
                        "signature_algorithms" => Ok(ExtensionType::SIGNATURE_ALGORITHMS),
                        "alpn" => Ok(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
                        "padding" => Ok(ExtensionType::PADDING),
                        "signed_certificate_timestamp" => Ok(ExtensionType::CERTIFICATE_TIMESTAMP),
                        "extended_master_secret" => Ok(ExtensionType::EXTENDED_MASTER_SECRET),
                        "session_ticket" => Ok(ExtensionType::SESSION_TICKET),
                        "supported_versions" => Ok(ExtensionType::SUPPORTED_VERSIONS),
                        "psk_key_exchange_modes" => Ok(ExtensionType::PSK_KEY_EXCHANGE_MODES),
                        "signature_algorithms_cert" => Ok(ExtensionType::SIGNATURE_ALGORITHMS_CERT),
                        "key_share" => Ok(ExtensionType::KEY_SHARE),
                        "renegotiation_info" => Ok(ExtensionType::RENEGOTIATE),
                        "delegated_credentials" => Ok(ExtensionType::DELEGATED_CREDENTIAL),
                        "application_settings" => Ok(ExtensionType::APPLICATION_SETTINGS),
                        "application_settings_old" => Ok(ExtensionType::APPLICATION_SETTINGS_OLD),
                        "encrypted_client_hello" | "ech" => {
                            Ok(ExtensionType::ENCRYPTED_CLIENT_HELLO)
                        }
                        "record_size_limit" => Ok(ExtensionType::RECORD_SIZE_LIMIT),
                        "cert_compression" => Ok(ExtensionType::CERT_COMPRESSION),
                        "pre_shared_key" => Ok(ExtensionType::PRE_SHARED_KEY),
                        "early_data" => Ok(ExtensionType::EARLY_DATA),
                        "cookie" => Ok(ExtensionType::COOKIE),
                        "certificate_authorities" => Ok(ExtensionType::CERTIFICATE_AUTHORITIES),
                        "next_proto_neg" | "npn" => Ok(ExtensionType::NEXT_PROTO_NEG),
                        "channel_id" => Ok(ExtensionType::CHANNEL_ID),
                        "quic_transport_parameters_legacy" => {
                            Ok(ExtensionType::QUIC_TRANSPORT_PARAMETERS_LEGACY)
                        }
                        "quic_transport_parameters" | "quic_transport_parameters_standard" => {
                            Ok(ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD)
                        }
                        _ => Err(anyhow::anyhow!("unknown extension: {s}")),
                    })
                    .collect()
            })
            .transpose()
    }
}

impl Http2Config {
    pub fn parse_pseudo_headers(&self) -> anyhow::Result<Vec<PseudoId>> {
        self.pseudo_headers_order
            .iter()
            .map(|name| match name.as_str() {
                ":method" => Ok(PseudoId::Method),
                ":path" => Ok(PseudoId::Path),
                ":authority" => Ok(PseudoId::Authority),
                ":scheme" => Ok(PseudoId::Scheme),
                _ => Err(anyhow::anyhow!("unknown pseudo header: {name}")),
            })
            .collect()
    }

    pub fn parse_settings_order(&self) -> anyhow::Result<Vec<SettingId>> {
        self.settings_order
            .iter()
            .map(|name| match name.to_ascii_lowercase().as_str() {
                "header_table_size" => Ok(SettingId::HeaderTableSize),
                "enable_push" => Ok(SettingId::EnablePush),
                "max_concurrent_streams" => Ok(SettingId::MaxConcurrentStreams),
                "initial_window_size" => Ok(SettingId::InitialWindowSize),
                "max_frame_size" => Ok(SettingId::MaxFrameSize),
                "max_header_list_size" => Ok(SettingId::MaxHeaderListSize),
                _ => Err(anyhow::anyhow!("unknown setting: {name}")),
            })
            .collect()
    }

    pub fn parse_priority_frames(&self) -> Vec<Priority> {
        self.priority_frames
            .as_ref()
            .map(|frames| {
                frames
                    .iter()
                    .map(|frame| {
                        Priority::new(
                            frame.stream_id.into(),
                            StreamDependency::new(
                                frame.depends_on.into(),
                                frame.weight,
                                frame.exclusive,
                            ),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn parse_headers_priority(&self) -> Option<StreamDependency> {
        self.headers_priority
            .as_ref()
            .map(|p| StreamDependency::new(p.depends_on.into(), p.weight, p.exclusive))
    }

    pub fn apply_http_headers(
        &self,
        incoming: &http::HeaderMap,
    ) -> anyhow::Result<Vec<(http::header::HeaderName, http::header::HeaderValue)>> {
        use http::header::{HeaderName, HeaderValue};
        use std::collections::HashSet;

        let mut result = Vec::new();
        let mut processed = HashSet::new();

        if let Some(order) = &self.headers_order {
            for configured_name in order {
                let name_lower = configured_name.to_ascii_lowercase();

                let name = HeaderName::from_bytes(name_lower.as_bytes()).map_err(|err| {
                    anyhow::anyhow!("[H2] invalid header name '{configured_name}': {err}")
                })?;

                processed.insert(name.clone());

                let configured_val = self
                    .http_headers
                    .as_ref()
                    .and_then(|map| map.get(&name_lower));

                match configured_val {
                    Some(Some(value)) => {
                        let value = HeaderValue::from_str(value).map_err(|err| {
                            anyhow::anyhow!("[H2] invalid value for header '{configured_name}': {err}")
                        })?;
                        result.push((name, value));
                    }
                    Some(None) => {}
                    None => {
                        for value in incoming.get_all(&name).iter() {
                            result.push((name.clone(), value.clone()));
                        }
                    }
                }
            }
        }

        if let Some(map) = &self.http_headers {
            for (configured_name, configured_value) in map {
                let name_lower = configured_name.to_ascii_lowercase();

                let name = HeaderName::from_bytes(name_lower.as_bytes()).map_err(|err| {
                    anyhow::anyhow!("[H2] invalid header name '{configured_name}': {err}")
                })?;

                if processed.contains(&name) {
                    continue;
                }

                processed.insert(name.clone());

                if let Some(value) = configured_value {
                    let value = HeaderValue::from_str(value).map_err(|err| {
                        anyhow::anyhow!("[H2] invalid value for header '{configured_name}': {err}")
                    })?;
                    result.push((name, value));
                }
            }
        }

        for (name, value) in incoming.iter() {
            if processed.contains(name) {
                continue;
            }
            result.push((name.clone(), value.clone()));
        }

        Ok(result)
    }

    pub fn encode_alps_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for setting_name in &self.settings_order {
            match setting_name.to_ascii_lowercase().as_str() {
                "header_table_size" => {
                    if let Some(val) = self.settings.header_table_size {
                        bytes.extend_from_slice(&1u16.to_be_bytes());
                        bytes.extend_from_slice(&val.to_be_bytes());
                    }
                }
                "enable_push" => {
                    let val = if self.settings.enable_push {
                        1u32
                    } else {
                        0u32
                    };
                    bytes.extend_from_slice(&2u16.to_be_bytes());
                    bytes.extend_from_slice(&val.to_be_bytes());
                }
                "max_concurrent_streams" => {
                    if let Some(val) = self.settings.max_concurrent_streams {
                        bytes.extend_from_slice(&3u16.to_be_bytes());
                        bytes.extend_from_slice(&val.to_be_bytes());
                    }
                }
                "initial_window_size" => {
                    if let Some(val) = self.settings.initial_window_size {
                        bytes.extend_from_slice(&4u16.to_be_bytes());
                        bytes.extend_from_slice(&val.to_be_bytes());
                    }
                }
                "max_frame_size" => {
                    if let Some(val) = self.settings.max_frame_size {
                        bytes.extend_from_slice(&5u16.to_be_bytes());
                        bytes.extend_from_slice(&val.to_be_bytes());
                    }
                }
                "max_header_list_size" => {
                    if let Some(val) = self.settings.max_header_list_size {
                        bytes.extend_from_slice(&6u16.to_be_bytes());
                        bytes.extend_from_slice(&val.to_be_bytes());
                    }
                }
                _ => {}
            }
        }

        bytes
    }
}

impl Http1Config {
    pub fn apply_http_headers(
        &self,
        incoming: &http::HeaderMap,
    ) -> anyhow::Result<Vec<(String, http::header::HeaderValue)>> {
        use http::header::{HeaderName, HeaderValue};
        use std::collections::HashSet;

        let mut result = Vec::new();
        let mut processed = HashSet::new();

        if let Some(order) = &self.headers_order {
            for configured_name in order {
                let name_lower = configured_name.to_ascii_lowercase();

                let header_name = HeaderName::from_bytes(name_lower.as_bytes()).map_err(|err| {
                    anyhow::anyhow!("[HTTP/1.1] invalid header name '{configured_name}': {err}")
                })?;

                processed.insert(header_name.clone());

                let configured_val = self
                    .http_headers
                    .as_ref()
                    .and_then(|map| map.get(&name_lower));

                match configured_val {
                    Some(Some(value)) => {
                        let value = HeaderValue::from_str(value).map_err(|err| {
                            anyhow::anyhow!(
                                "[HTTP/1.1] invalid value for header '{configured_name}': {err}"
                            )
                        })?;
                        result.push((configured_name.clone(), value));
                    }
                    Some(None) => {}
                    None => {
                        for value in incoming.get_all(&header_name).iter() {
                            result.push((configured_name.clone(), value.clone()));
                        }
                    }
                }
            }
        }
        if let Some(map) = &self.http_headers {
            for (configured_name, configured_value) in map {
                let name_lower = configured_name.to_ascii_lowercase();

                let header_name = HeaderName::from_bytes(name_lower.as_bytes()).map_err(|err| {
                    anyhow::anyhow!("[HTTP/1.1] invalid header name '{configured_name}': {err}")
                })?;

                if processed.contains(&header_name) {
                    continue;
                }

                processed.insert(header_name.clone());

                if let Some(value) = configured_value {
                    let value = HeaderValue::from_str(value).map_err(|err| {
                        anyhow::anyhow!("[HTTP/1.1] invalid value for header '{configured_name}': {err}")
                    })?;
                    result.push((configured_name.clone(), value));
                }
            }
        }
        for (name, value) in incoming.iter() {
            if processed.contains(name) {
                continue;
            }
            result.push((name.as_str().to_string(), value.clone()));
        }

        Ok(result)
    }
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.trim().is_empty()))
}

fn default_port() -> u16 {
    9090
}
