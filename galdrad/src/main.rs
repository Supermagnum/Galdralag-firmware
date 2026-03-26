//! Local REST daemon: JSON API for Galdra (contacts, groups, audit, device status).

use clap::Parser;
use galdra_core_host::config::{
    database_key_from_env, default_config_path, default_database_path, load_config, Config,
};
use galdra_core_host::db::Db;
use galdra_core_host::GaldraError;
use std::path::{Path, PathBuf};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "galdrad", about = "Local Galdra REST daemon (HTTP JSON API)")]
struct Cli {
    /// Listen address (default: localhost only).
    #[arg(long, default_value = "127.0.0.1:8742")]
    listen: std::net::SocketAddr,
    /// Configuration file path (default: platform config dir).
    #[arg(long)]
    config: Option<PathBuf>,
    /// SQLite database path (overrides config).
    #[arg(long)]
    db: Option<PathBuf>,
}

fn load_app_config(path: Option<&Path>) -> Result<Config, GaldraError> {
    let p = if let Some(p) = path {
        p.to_path_buf()
    } else {
        default_config_path()?
    };
    load_config(&p)
}

fn open_database(config: &Config, db_override: Option<&Path>) -> Result<Db, GaldraError> {
    let path = if let Some(p) = db_override {
        p.to_path_buf()
    } else if let Some(p) = &config.database_path {
        p.clone()
    } else {
        default_database_path()?
    };
    let key = database_key_from_env(config)?;
    Db::open(&path, key.as_deref())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = load_app_config(cli.config.as_deref())?;
    let db = open_database(&config, cli.db.as_deref())?;
    let state = galdrad::state::AppState::new(db);
    let app = galdrad::api::router(state);

    let listener = TcpListener::bind(cli.listen).await?;
    tracing::info!(address = %cli.listen, "galdrad listening");
    axum::serve(listener, app).await?;
    Ok(())
}
