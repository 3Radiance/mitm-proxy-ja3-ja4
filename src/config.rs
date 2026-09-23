use btls::ssl::ExtensionType;
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
    pub settings: HashMap<String, Value>,
    pub settings_order: Vec<String>,
    pub connection_window_update: u32,
    #[serde(default)]
    pub priority_frames: Vec<H2PriorityFrame>,
    pub pseudo_headers_order: Vec<String>,
    pub headers_order: Vec<String>,
    pub http_headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct H2PriorityFrame {
    pub stream_id: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u8,
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

    pub fn parse_extension(s: &str) -> Result<ExtensionType, String> {
        if let Some(hex) = s.strip_prefix("0x") {
            let code = u16::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
            return Ok(ExtensionType::from(code));
        }
        match s {
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
        }
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
