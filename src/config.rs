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
    pub tcp: TcpConfig,
    pub tls: TlsConfig,
    pub http2: Http2Config,
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
    pub min_version: String,
    pub max_version: String,
    pub cipher_suites: Vec<String>,
    pub alpn: Vec<String>,
    pub curves: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub extensions_order: Vec<String>,
    pub cert_compression: Vec<String>,
    pub grease_enabled: bool,
    pub enable_ech: bool,
    #[serde(default = "default_record_size_limit")]
    pub record_size_limit: u16,
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

fn default_record_size_limit() -> u16 {
    16384
}
