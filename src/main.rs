mod config;
mod domain;
mod h1_fingerprint;
mod h2_fingerprint;
mod logging;
mod proxy;
mod tcp_fingerprint;
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
    pub tcp: Arc<TcpConfig>,
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
            tcp: Arc::new(profile.tcp.clone()),
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

    let tcp = Arc::new(config.tcp.clone());
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
        crate::log_tag!(info, "CFG", "Loaded {} domain profiles", domains.len());
    }

    let mut tcp_domains: HashMap<u32, Arc<TcpConfig>> = HashMap::new();
    for (_, data) in domains.iter() {
        if let Some(mark) = data.tcp.mark {
            tcp_domains.insert(mark, Arc::clone(&data.tcp));
        }
    }
    crate::log_tag!(
        info,
        "CFG",
        "Loaded {} router domain marks",
        tcp_domains.len()
    );

    let router = Arc::new(crate::proxy::tcp::Router {
        default: default_data,
        domains: Arc::new(domains),
    });
    let data = ProxyConfig { port, router };

    let inflight = Arc::clone(&data.router.default.cache.inflight);

    tokio::spawn(async move { gc(inflight).await });

    crate::log_tag!(info, "CFG", "Loaded config: {}", path.display());

    let tcp_clone = Arc::clone(&tcp);
    let tcp_domains_clone = tcp_domains.clone();
    let tcp_clone_iptables = Arc::clone(&tcp);
    let tcp_domains_clone_iptables = tcp_domains.clone();
    let tcp_shutdown = Arc::clone(&tcp);
    let tcp_domains_shutdown = tcp_domains.clone();

    let nfqueue_on = config.tcp.mark.is_some();

    if nfqueue_on {
        if config.tcp.qnum_syn == config.tcp.qnum_tcp {
            return Err(anyhow::anyhow!("qnum_syn and qnum_tcp must be different"));
        }
        tokio::spawn(async move { tcp_fingerprint::syn::start_qnum_syn(tcp, tcp_domains).await });

        tokio::spawn(async move {
            tcp_fingerprint::tcp::start_qnum_tcp(tcp_clone, tcp_domains_clone).await
        });

        if let Err(e) = tcp_fingerprint::iptables::apply_auto_iptables(
            tcp_clone_iptables,
            tcp_domains_clone_iptables,
        ) {
            crate::log_tag!(warn, "IPT", "auto iptables failed: {:#}", e);
        }
    }

    let mut exit_code = 0;

    tokio::select! {
        res = proxy::tcp::connection(data) => {
            if let Err(e) = res {
                crate::log_tag!(error, "TCP", "listener exited: {:#}", e);
                exit_code = 1;
            }
        }
        _ = tokio::signal::ctrl_c() => {
            crate::log_tag!(info, "Runtime", "Ctrl+C received, shutting down...");
            exit_code = 1;
        }
    }

    if nfqueue_on {
        if let Err(e) =
            tcp_fingerprint::iptables::remove_auto_iptables(tcp_shutdown, tcp_domains_shutdown)
        {
            crate::log_tag!(warn, "IPT", "iptables cleanup failed: {:#}", e);
        } else {
            crate::log_tag!(info, "IPT", "iptables rules removed");
        }
    }

    std::process::exit(exit_code);
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
