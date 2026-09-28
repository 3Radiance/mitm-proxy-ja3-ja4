mod config;
mod domain;
mod h1_fingerprint;
mod h2_fingerprint;
mod logging;
mod proxy;
mod tls_fingerprint;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use crate::config::*;
use crate::domain::DomainConfig;
use crate::tls_fingerprint::cert::*;
use crate::tls_fingerprint::ech::EchCache;
use moka::future::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(short, long)]
    domain: Option<PathBuf>,
}

pub struct ProxyConfig {
    pub port: u16,
    pub router: Arc<crate::proxy::tcp::Router>,
}

#[derive(Clone)]
pub struct Data {
    pub ca: Arc<MitmCa>,
    pub tls: Arc<TlsConfig>,
    pub http2: Arc<Http2Config>,
    pub http1: Arc<Http1Config>,
    pub upstream: Arc<Option<String>>,
    pub cache: Arc<EchCache>,
}

impl Data {
    pub fn from_profile(profile: &ProfileConfig, ca: &Arc<MitmCa>, cache: &Arc<EchCache>) -> Self {
        Self {
            ca: Arc::clone(ca),
            tls: Arc::new(profile.tls.clone()),
            http2: Arc::new(profile.http2.clone()),
            http1: Arc::new(profile.http1.clone()),
            upstream: Arc::new(profile.config.upstream_proxy.clone()),
            cache: Arc::clone(cache),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

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

    let cache: Cache<String, Option<Vec<u8>>> = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(3600))
        .build();
    let cache = Arc::new(EchCache {
        cache,
        inflight: Arc::new(Mutex::new(HashMap::new())),
    });

    let default_data = Data::from_profile(config, &ca, &cache);
    let port = config.config.port;

    let mut domains: HashMap<String, Data> = HashMap::new();
    if let Some(path_domain) = args.domain {
        let config_domain = DomainConfig::load_from_file(
            path_domain
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path"))?,
        )?;
        for (pattern, overlay) in config_domain.overlays.iter() {
            let merged = overlay.merge_into(config);
            domains.insert(pattern.clone(), Data::from_profile(&merged, &ca, &cache));
        }
        tracing::info!("[CFG] Loaded {} domain profiles", domains.len());
    }

    let router = Arc::new(crate::proxy::tcp::Router {
        default: default_data,
        domains: Arc::new(domains),
    });
    let data = ProxyConfig { port, router };

    let inflight = Arc::clone(&data.router.default.cache.inflight);

    tokio::spawn(async move { gc(inflight).await });

    tracing::info!("[CFG] Loaded config: {:#?}", config);

    proxy::tcp::connection(data).await?;

    Ok(())
}

async fn gc(inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>) {
    let mut interval = tokio::time::interval(Duration::from_mins(5));
    loop {
        interval.tick().await;
        let mut vec: Vec<String> = Vec::new();
        let mut guard = inflight.lock().await;
        for i in guard.iter() {
            let (domain, mutex) = i;
            match mutex.try_lock() {
                Ok(_) => {}
                Err(_) => continue,
            }
            match Arc::strong_count(mutex) {
                1 => {}
                _ => continue,
            }
            vec.push(domain.clone());
        }
        for i in vec {
            guard.remove(&i);
        }
    }
}
