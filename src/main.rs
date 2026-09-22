mod proxy;
mod tls;

use crate::tls::cert::MitmCa;
use clap::Parser;
use std::sync::Arc;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 9090)]
    port: u16,
    #[arg(long)]
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
    proxy::tcp::connection(data).await?;
    Ok(())
}
