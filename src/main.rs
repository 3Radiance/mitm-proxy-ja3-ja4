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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let upstream = get_upstream(&args);
    let ca = Arc::new(MitmCa::load_or_create()?);
    proxy::tcp::connection(ca, Arc::new(upstream), args.port).await?;
    Ok(())
}
