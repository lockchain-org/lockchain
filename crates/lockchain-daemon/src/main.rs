//! Background daemon that watches the USB token and keeps datasets unlocked.

use anyhow::{Context, Result};
use lockchain_core::{
    config::{LockchainConfig, DEFAULT_CONFIG_PATH},
    logging,
    service::{LockchainService, UnlockOptions},
    workflow,
};
use lockchain_zfs::SystemZfsProvider;
use log::{error, info, warn};
use std::sync::{Arc, Mutex};
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::TcpListener,
    select, signal,
    sync::watch,
    time::{interval, Duration, Instant},
};

mod usb;

/// Tracks whether USB discovery and unlock routines consider the world healthy.
#[derive(Default)]
struct HealthState {
    usb_ready: bool,
    unlock_ready: bool,
}

/// Shared handle used to notify other tasks when overall health changes.
#[derive(Clone)]
struct HealthChannel {
    inner: Arc<HealthInner>,
}

struct HealthInner {
    state: Mutex<HealthState>,
    tx: watch::Sender<bool>,
}

impl HealthChannel {
    /// Create a new channel bound to the provided watch sender.
    fn new(tx: watch::Sender<bool>) -> Self {
        Self {
            inner: Arc::new(HealthInner {
                state: Mutex::new(HealthState::default()),
                tx,
            }),
        }
    }

    /// Record the latest USB availability status.
    fn set_usb_ready(&self, ready: bool) {
        let mut state = self.inner.state.lock().unwrap();
        let changed = state.usb_ready != ready;
        state.usb_ready = ready;
        let healthy = state.usb_ready && state.unlock_ready;
        drop(state);
        if changed {
            let _ = self.inner.tx.send(healthy);
        }
    }

    /// Record whether unlock attempts have been succeeding lately.
    fn set_unlock_ready(&self, ready: bool) {
        let mut state = self.inner.state.lock().unwrap();
        let changed = state.unlock_ready != ready;
        state.unlock_ready = ready;
        let healthy = state.usb_ready && state.unlock_ready;
        drop(state);
        if changed {
            let _ = self.inner.tx.send(healthy);
        }
    }
}

/// Entry point for the Tokio runtime; logs failures before exit.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(err) = run().await {
        error!("daemon exit: {err:?}");
        std::process::exit(1);
    }
}

/// Load configuration, start background tasks, and juggle shutdown signals.
async fn run() -> Result<()> {
    logging::init("info");
    let config_path =
        std::env::var("LOCKCHAIN_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let config_path = PathBuf::from(config_path);
    let config = Arc::new(
        LockchainConfig::load_or_bootstrap(&config_path)
            .with_context(|| format!("load config {}", config_path.display()))?,
    );

    workflow::ensure_privilege_support().map_err(anyhow::Error::new)?;

    if config.path != config_path {
        warn!(
            "configuration missing at {}; using bootstrap at {}",
            config_path.display(),
            config.path.display()
        );
    }

    info!(
        "LockChain daemon booting (config: {})",
        config.path.display()
    );

    let provider = SystemZfsProvider::from_config(&config).context("initialise zfs provider")?;
    let service = Arc::new(LockchainService::new(config.clone(), provider));

    // health status broadcast (true = ready, false = degraded)
    let (health_tx, health_rx) = watch::channel(false);
    let health_channel = HealthChannel::new(health_tx.clone());

    let usb_handle = tokio::spawn(usb::watch_usb(config.clone(), health_channel.clone()));
    let unlock_handle = tokio::spawn(periodic_unlock(
        service.clone(),
        config.clone(),
        health_channel.clone(),
    ));
    let health_handle = tokio::spawn(health_server(health_rx));

    select! {
        res = usb_handle => res??,
        res = unlock_handle => res??,
        res = health_handle => res??,
        _ = signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    Ok(())
}

/// Periodically attempt to unlock the configured dataset and update health.
async fn periodic_unlock(
    service: Arc<LockchainService<SystemZfsProvider>>,
    config: Arc<LockchainConfig>,
    health: HealthChannel,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(30));
    let mut last_success = Instant::now();
    loop {
        ticker.tick().await;
        let dataset = config.policy.datasets.first().cloned().unwrap_or_default();
        if dataset.is_empty() {
            warn!("no datasets configured; daemon idle");
            continue;
        }

        let key_path = config.key_hex_path();
        let key_ready = std::fs::metadata(&key_path)
            .map(|meta| meta.is_file() && meta.len() == 32)
            .unwrap_or(false);
        if !key_ready {
            health.set_unlock_ready(false);
            continue;
        }

        match service.unlock_with_retry(&dataset, UnlockOptions::default()) {
            Ok(report) => {
                if report.already_unlocked {
                    info!("dataset {dataset} already unlocked");
                } else {
                    info!("unlocked {dataset} with {} nodes", report.unlocked.len());
                }
                health.set_unlock_ready(true);
                last_success = Instant::now();
            }
            Err(err) => {
                warn!("unlock attempt failed for {dataset}: {err}");
                health.set_unlock_ready(false);
                // degrade if failure lasts >5 minutes
                if last_success.elapsed() > Duration::from_secs(300) {
                    warn!(
                        "dataset {dataset} has been locked for {:?}",
                        last_success.elapsed()
                    );
                }
            }
        }
    }
}

/// Expose a bare-bones HTTP endpoint for readiness checks.
async fn health_server(status_rx: watch::Receiver<bool>) -> Result<()> {
    let addr: SocketAddr = std::env::var("LOCKCHAIN_HEALTH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()
        .context("parse LOCKCHAIN_HEALTH_ADDR")?;

    let listener = TcpListener::bind(addr).await?;
    info!("health endpoint listening on http://{addr}");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let healthy = *status_rx.borrow();
        let body = if healthy { "OK" } else { "DEGRADED" };
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        if let Err(err) = stream.write_all(response.as_bytes()).await {
            warn!("failed to respond to {peer}: {err}");
        }
    }
}
