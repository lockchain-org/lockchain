//! Polling loop that checks whether the USB key material is present on disk.

use anyhow::Result;
use lockchain_core::LockchainConfig;
use log::{info, warn};
use std::fs;
use std::sync::Arc;
use tokio::time::{interval, Duration};

use crate::HealthChannel;

/// Periodically inspect the expected key path and update health status.
pub async fn watch_usb(config: Arc<LockchainConfig>, health: HealthChannel) -> Result<()> {
    let key_path = config.key_hex_path();
    let mut ticker = interval(Duration::from_secs(5));
    let mut last_state: Option<bool> = None;

    loop {
        ticker.tick().await;
        let present = match fs::metadata(&key_path) {
            Ok(meta) => meta.is_file() && meta.len() == 32,
            Err(_) => false,
        };

        if last_state != Some(present) {
            if present {
                info!(
                    "USB key material ready at {} (32 bytes detected).",
                    key_path.display()
                );
            } else {
                warn!(
                    "USB key material at {} missing or invalid; waiting for lockchain-key-usb.",
                    key_path.display()
                );
            }
            last_state = Some(present);
        }

        health.set_usb_ready(present);
    }
}
