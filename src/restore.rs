//! Reconnect + guaranteed-restore guard (Rust equivalent of Python try/finally).

use anyhow::Result;
use std::time::Duration;

use crate::netsh;

/// Reconnect to `target`, retrying up to 8 times, verifying via show_interface.
pub fn reconnect(target: &str) -> Result<bool> {
    for attempt in 1..=8 {
        let out = netsh::connect(target)?;
        if out.ok() {
            std::thread::sleep(Duration::from_secs(5));
            let iface = netsh::show_interface()?;
            if iface.ssid.as_deref() == Some(target) {
                tracing::info!("reconnect: connected to {} (attempt {})", target, attempt);
                return Ok(true);
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    let iface = netsh::show_interface()?;
    let on = iface.ssid.as_deref() == Some(target);
    tracing::warn!(
        "reconnect: final state ssid={:?} (target {})",
        iface.ssid,
        target
    );
    Ok(on)
}

/// Drop guard that reconnects to `ssid` when dropped (including panics unwinding).
pub struct RestoreGuard {
    pub ssid: String,
    pub done: bool,
}

impl RestoreGuard {
    pub fn new(ssid: impl Into<String>) -> Self {
        Self { ssid: ssid.into(), done: false }
    }
}

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        tracing::info!("[RestoreGuard] restoring connection to {} ...", self.ssid);
        // Best effort: never panic in drop.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reconnect(&self.ssid.clone());
        }));
    }
}
