use btls::ssl::ExtensionType;
use http2::frame::{Priorities, Priority, StreamDependency};
use http2::frame::{PseudoId, PseudoOrder, PseudoOrderBuilder};
use http2::frame::{SettingId, SettingsOrder, SettingsOrderBuilder};
use serde::Deserialize;
use serde_json::Value;
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
    pub extensions_order: Vec<String>,
    pub cert_compression: Vec<String>,
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
    pub headers_order: Vec<String>,
    pub http_headers: HashMap<String, Option<String>>,
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
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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

    pub fn parse_extension(&self) -> Result<Vec<ExtensionType>, String> {
        self.extensions_order
            .iter()
            .map(|s| match s.as_str() {
                "server_name" => Ok(ExtensionType::SERVER_NAME),
                "status_request" => Ok(ExtensionType::STATUS_REQUEST),
                "supported_groups" => Ok(ExtensionType::SUPPORTED_GROUPS),
                "ec_point_formats" => Ok(ExtensionType::EC_POINT_FORMATS),
                "signature_algorithms" => Ok(ExtensionType::SIGNATURE_ALGORITHMS),
                "alpn" => Ok(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
                "padding" => Ok(ExtensionType::PADDING),
                "extended_master_secret" => Ok(ExtensionType::EXTENDED_MASTER_SECRET),
                "session_ticket" => Ok(ExtensionType::SESSION_TICKET),
                "supported_versions" => Ok(ExtensionType::SUPPORTED_VERSIONS),
                "psk_key_exchange_modes" => Ok(ExtensionType::PSK_KEY_EXCHANGE_MODES),
                "signature_algorithms_cert" => Ok(ExtensionType::SIGNATURE_ALGORITHMS_CERT),
                "key_share" => Ok(ExtensionType::KEY_SHARE),
                "renegotiation_info" => Ok(ExtensionType::RENEGOTIATE),
                "delegated_credentials" => Ok(ExtensionType::DELEGATED_CREDENTIAL),
                "application_settings" => Ok(ExtensionType::APPLICATION_SETTINGS),
                "encrypted_client_hello" => Ok(ExtensionType::ENCRYPTED_CLIENT_HELLO),
                "record_size_limit" => Ok(ExtensionType::RECORD_SIZE_LIMIT),
                "cert_compression" => Ok(ExtensionType::CERT_COMPRESSION),
                "pre_shared_key" => Ok(ExtensionType::PRE_SHARED_KEY),
                "early_data" => Ok(ExtensionType::EARLY_DATA),
                "cookie" => Ok(ExtensionType::COOKIE),
                _ => Err(format!("unknown extension: {s}")),
            })
            .collect()
    }
}

impl Http2Config {
    pub fn parse_pseudo_headers(&self) -> Result<Vec<PseudoId>, String> {
        self.pseudo_headers_order
            .iter()
            .map(|name| match name.as_str() {
                ":method" => Ok(PseudoId::Method),
                ":path" => Ok(PseudoId::Path),
                ":authority" => Ok(PseudoId::Authority),
                ":scheme" => Ok(PseudoId::Scheme),
                _ => Err(format!("unknown pseudo header: {name}")),
            })
            .collect()
    }

    pub fn parse_settings_order(&self) -> Result<Vec<SettingId>, String> {
        self.settings_order
            .iter()
            .map(|name| match name.to_ascii_lowercase().as_str() {
                "header_table_size" => Ok(SettingId::HeaderTableSize),
                "enable_push" => Ok(SettingId::EnablePush),
                "max_concurrent_streams" => Ok(SettingId::MaxConcurrentStreams),
                "initial_window_size" => Ok(SettingId::InitialWindowSize),
                "max_frame_size" => Ok(SettingId::MaxFrameSize),
                "max_header_list_size" => Ok(SettingId::MaxHeaderListSize),
                _ => Err(format!("unknown setting: {name}")),
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
    ) -> Result<Vec<(http::header::HeaderName, http::header::HeaderValue)>, String> {
        use http::header::{HeaderName, HeaderValue};
        use std::collections::HashSet;

        let mut result = Vec::new();
        let mut processed = HashSet::new();

        for configured_name in &self.headers_order {
            let name_lower = configured_name.to_ascii_lowercase();

            let name = HeaderName::from_bytes(name_lower.as_bytes())
                .map_err(|err| format!("invalid header name '{configured_name}': {err}"))?;

            processed.insert(name.clone());

            match self.http_headers.get(&name_lower) {
                Some(Some(value)) => {
                    let value = HeaderValue::from_str(value).map_err(|err| {
                        format!("invalid value for header '{configured_name}': {err}")
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

        for (configured_name, configured_value) in &self.http_headers {
            let name_lower = configured_name.to_ascii_lowercase();

            let name = HeaderName::from_bytes(name_lower.as_bytes())
                .map_err(|err| format!("invalid header name '{configured_name}': {err}"))?;

            if processed.contains(&name) {
                continue;
            }

            processed.insert(name.clone());

            match configured_value {
                Some(value) => {
                    let value = HeaderValue::from_str(value).map_err(|err| {
                        format!("invalid value for header '{configured_name}': {err}")
                    })?;

                    result.push((name, value));
                }

                None => {}
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
