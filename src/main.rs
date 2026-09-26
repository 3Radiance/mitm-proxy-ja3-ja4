mod config;
mod h1_fingerptint;
mod h2_fingerprint;
mod proxy;
mod tls_fingerprint;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use crate::config::*;
use crate::tls_fingerprint::cert::*;
use std::sync::Arc;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

pub struct ProxyConfig {
    pub port: u16,
    pub ctx: Data,
}

#[derive(Clone)]
pub struct Data {
    pub ca: Arc<MitmCa>,
    pub tls: Arc<TlsConfig>,
    pub http2: Arc<Http2Config>,
    pub http1: Arc<Http1Config>,
    pub upstream: Arc<Option<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let path = args
        .config
        .ok_or_else(|| anyhow::anyhow!("Pass the configuration file using the -c flag"))?;

    let config = AppConfig::load_from_file(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
    )?;
    let config = config
        .profiles
        .values()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No Profile Configured"))?;

    let ca = Arc::new(MitmCa::load_or_create(
        &config.config.cert,
        &config.config.key,
    )?);

    let tls = Arc::new(config.tls.clone());
    let http2 = Arc::new(config.http2.clone());
    let http1 = Arc::new(config.http1.clone());
    let upstream = Arc::new(config.config.upstream_proxy.clone());
    let port = config.config.port;

    let data = ProxyConfig {
        port,
        ctx: Data {
            ca,
            tls,
            http2,
            http1,
            upstream,
        },
    };

    println!("[INFO] Loaded config: {:#?}", config);

    proxy::tcp::connection(data).await?;
    Ok(())
}
