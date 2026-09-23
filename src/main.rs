mod config;
mod proxy;
mod tls;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::AppConfig;
use crate::tls::cert::MitmCa;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(short, long, default_value_t = 9090)]
    port: u16,
    #[arg(short, long)]
    upstream: Option<String>,
}

fn get_upstream(args: &Args) -> Option<String> {
    match &args.upstream {
        Some(n) => Some(n.clone()),
        None => None,
    }
}

struct Data {
    upstream: Arc<Option<String>>,
    ca: Arc<MitmCa>,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let upstream = get_upstream(&args);
    let ca = Arc::new(MitmCa::load_or_create()?);
    let data = Arc::new(Data {
        upstream: Arc::new(upstream),
        ca: ca.clone(),
        port: args.port,
    });
    match args.config {
        Some(path) => {
            let config = AppConfig::load_from_file(path.to_str().unwrap())?;
            println!("[INFO] Loaded config: {:#?}", config);
            proxy::tcp::connection(data, config).await?;
        }
        None => {
            return Err("Pass the configuration file using the -c flag"
                .to_string()
                .into());
        }
    }
    Ok(())
}
