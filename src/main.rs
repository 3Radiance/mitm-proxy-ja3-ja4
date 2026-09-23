mod config;
mod fingerprint;
mod proxy;

use clap::Parser;
use std::path::PathBuf;

use crate::config::AppConfig;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    match args.config {
        Some(path) => {
            let config = AppConfig::load_from_file(path.to_str().ok_or("Invalid path")?)?;
            println!("[INFO] Loaded config: {:#?}", config);
            proxy::tcp::connection(config).await?;
        }
        None => {
            return Err("Pass the configuration file using the -c flag"
                .to_string()
                .into());
        }
    }
    Ok(())
}
