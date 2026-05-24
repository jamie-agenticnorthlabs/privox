//! `privox` — Privacy proxy for LLM calls.
//!
//! CLI parsing, config loading, vault initialization, and server startup.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing::warn;
use uuid::Uuid;

mod config;
mod detector;
mod detokenizer;
mod error;
mod proxy;
mod server;
mod tokenizer;
mod types;
mod vault;

use config::Config;
use vault::{SqliteVault, Vault};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "privox", version, about = "Privacy proxy for LLM calls")]
struct Cli {
    /// Path to config file.
    #[arg(long, env = "PRIVOX_CONFIG", default_value = "~/.privox/config.toml")]
    config: PathBuf,

    /// Override listen address.
    #[arg(long, env = "PRIVOX_PROXY_LISTEN")]
    listen: Option<String>,

    /// Override upstream URL.
    #[arg(long, env = "PRIVOX_UPSTREAM_URL")]
    upstream: Option<String>,

    /// Override log level.
    #[arg(long, env = "PRIVOX_LOG_LEVEL")]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Vault management subcommands.
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Validate config and connectivity, then exit.
    Check,
    /// Generate a new installation secret and exit (run once on first install).
    Init,
}

#[derive(Subcommand)]
enum VaultAction {
    /// Purge all expired vault entries.
    Purge,
    /// Print vault entry counts by entity type.
    Stats,
    /// Delete all vault entries (requires --confirm).
    Clear {
        #[arg(long)]
        confirm: bool,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cfg = load_config(&cli)?;
    init_tracing(&cfg.log.level);

    match cli.command {
        Some(Commands::Init) => cmd_init(&cfg),
        Some(Commands::Vault { action }) => cmd_vault(&cfg, action),
        Some(Commands::Check) => cmd_check(&cfg),
        None => cmd_serve(cfg),
    }
}

// ── Subcommand implementations ────────────────────────────────────────────────

fn cmd_init(cfg: &Config) -> anyhow::Result<()> {
    let secret_path = secret_path(cfg);
    if secret_path.exists() {
        anyhow::bail!(
            "Secret file already exists at {}. \
             Delete it manually if you want to generate a new installation (this will \
             invalidate all existing vault entries).",
            secret_path.display()
        );
    }
    let secret = generate_secret();
    write_secret_file(&secret_path, &secret)?;
    println!("Installation secret written to {}", secret_path.display());
    println!("Keep this file safe. Losing it will invalidate all vault entries.");
    Ok(())
}

fn cmd_vault(cfg: &Config, action: VaultAction) -> anyhow::Result<()> {
    let vault = open_vault(cfg)?;
    match action {
        VaultAction::Purge => {
            let n = vault.purge_expired().context("purge_expired failed")?;
            println!("Purged {n} expired vault entries.");
        }
        VaultAction::Stats => {
            let stats = vault.stats().context("stats failed")?;
            if stats.is_empty() {
                println!("Vault is empty.");
            } else {
                for (entity_type, count) in stats {
                    println!("  {entity_type}: {count}");
                }
            }
        }
        VaultAction::Clear { confirm } => {
            if !confirm {
                eprintln!("Pass --confirm to delete all vault entries.");
                std::process::exit(1);
            }
            let n = vault.clear_all().context("clear_all failed")?;
            println!("Cleared {n} vault entries.");
        }
    }
    Ok(())
}

fn cmd_check(cfg: &Config) -> anyhow::Result<()> {
    let vault = open_vault(cfg)?;
    let stats = vault.stats().context("vault stats failed")?;
    println!("Config:  OK");
    println!("Vault:   OK ({} entity type(s) present)", stats.len());
    println!("Upstream URL: {}", cfg.upstream.url);
    println!("Listen:  {}", cfg.proxy.listen);
    Ok(())
}

fn cmd_serve(cfg: Config) -> anyhow::Result<()> {
    let vault = Arc::new(open_vault(&cfg)?);
    let secret = load_secret(&cfg)?;
    let session_id = Uuid::new_v4();

    // Build the detector pipeline.
    let mut detectors: Vec<Box<dyn detector::Detector>> =
        vec![Box::new(detector::regex::RegexDetector::new())];
    if cfg.detection.ner_enabled() {
        detectors.push(Box::new(detector::ner::NerDetector::new(
            cfg.detection.ner.clone(),
        )));
    }
    if cfg.detection.presidio_enabled() {
        detectors.push(Box::new(detector::presidio::PresidioDetector::new(
            cfg.detection.presidio.clone(),
        )));
    }

    let state = Arc::new(server::AppState {
        pipeline: detector::DetectorPipeline::new(detectors),
        tokenizer: tokenizer::Tokenizer::new(
            Arc::clone(&vault) as Arc<dyn Vault>,
            secret,
            session_id,
            cfg.vault.ttl_hours,
        ),
        detokenizer: detokenizer::Detokenizer::new(Arc::clone(&vault) as Arc<dyn Vault>),
        upstream: proxy::UpstreamClient::new(&cfg.upstream),
    });

    let listen = cfg.proxy.listen.clone();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?
        .block_on(server::run(state, &listen))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_config(cli: &Cli) -> anyhow::Result<Config> {
    let path = expand_tilde(&cli.config);
    let cfg = if path.exists() {
        Config::load(&path)
            .with_context(|| format!("failed to load config from {}", path.display()))?
    } else {
        warn!(path = %path.display(), "config file not found — using defaults");
        Config::default()
    };

    // Apply CLI overrides on top of config/env overrides.
    let mut cfg = cfg;
    if let Some(listen) = &cli.listen {
        cfg.proxy.listen = listen.clone();
    }
    if let Some(url) = &cli.upstream {
        cfg.upstream.url = url.clone();
    }
    if let Some(level) = &cli.log_level {
        cfg.log.level = level.clone();
    }
    Ok(cfg)
}

fn open_vault(cfg: &Config) -> anyhow::Result<SqliteVault> {
    let secret = load_secret(cfg)?;
    let db_path = expand_tilde(&PathBuf::from(&cfg.vault.path));
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create vault directory {}", parent.display()))?;
    }
    SqliteVault::open(&db_path, &secret)
        .with_context(|| format!("failed to open vault at {}", db_path.display()))
}

fn secret_path(cfg: &Config) -> PathBuf {
    let vault_path = expand_tilde(&PathBuf::from(&cfg.vault.path));
    vault_path
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .join("secret.key")
}

fn load_secret(cfg: &Config) -> anyhow::Result<Vec<u8>> {
    let path = secret_path(cfg);
    std::fs::read(&path).with_context(|| {
        format!(
            "Installation secret not found at {}. \
             Run `privox init` to generate a new installation.",
            path.display()
        )
    })
}

fn generate_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut secret = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

fn write_secret_file(path: &PathBuf, secret: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    std::fs::write(path, secret)
        .with_context(|| format!("failed to write secret to {}", path.display()))?;

    // Set 0600 permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set 0600 permissions on {}", path.display()))?;
    }
    Ok(())
}

fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs_or_home() {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

fn dirs_or_home() -> Option<String> {
    // std::env::home_dir() is deprecated but there is no approved alternative dep.
    // On Windows this returns USERPROFILE or HOMEDRIVE+HOMEPATH; on Unix it returns HOME.
    #[allow(deprecated)]
    std::env::home_dir().map(|p| p.to_string_lossy().into_owned())
}

fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).json().init();
}
