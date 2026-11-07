//! Multi-round WiFi scan. Optionally disconnects first (more APs visible),
//! then restores. Writes logs/scan_results.json.

use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::config::ScanCfg;
use crate::netsh;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub duration_sec: u64,
    pub rounds: u32,
    pub total_ssids: usize,
    pub networks: BTreeMap<String, netsh::NetworkInfo>,
}

/// Run scan. If `disconnect_first`, disconnect then reconnect afterwards via `restore_to`.
pub fn scan(cfg: &ScanCfg, restore_to: Option<&str>) -> Result<ScanResult> {
    if cfg.disconnect_first {
        tracing::info!("scan: disconnecting for better visibility...");
        let _ = netsh::disconnect();
        std::thread::sleep(Duration::from_secs(4));
    }

    let mut seen: BTreeMap<String, netsh::NetworkInfo> = BTreeMap::new();
    let mut rounds: u32 = 0;
    let t0 = Instant::now();
    let interval = Duration::from_secs(cfg.interval_sec.max(1));

    while t0.elapsed().as_secs() < cfg.duration_sec {
        match netsh::show_networks() {
            Ok(nets) => {
                for n in nets {
                    seen.entry(n.ssid.clone()).or_insert(n);
                }
            }
            Err(e) => tracing::warn!("scan round {}: {}", rounds + 1, e),
        }
        rounds += 1;
        if rounds % 5 == 0 {
            tracing::info!("scan: round {} -> {} SSIDs", rounds, seen.len());
        }
        std::thread::sleep(interval);
    }

    let result = ScanResult {
        duration_sec: cfg.duration_sec,
        rounds,
        total_ssids: seen.len(),
        networks: seen,
    };

    for (ssid, info) in result.networks.iter().take(30) {
        tracing::info!(
            "scan: {:24} bssid={:?} ch={:?} auth={:?}",
            ssid,
            info.bssid,
            info.channel,
            info.auth
        );
    }

    if cfg.disconnect_first {
        if let Some(target) = restore_to {
            tracing::info!("scan: reconnecting to {} ...", target);
            let ok = crate::restore::reconnect(target)?;
            tracing::info!("scan: restore {}", if ok { "OK" } else { "FAILED" });
        }
    }

    Ok(result)
}

/// Save result JSON to logs/scan_results.json.
pub fn save_result(res: &ScanResult, logs_dir: &std::path::Path) -> Result<()> {
    let path = logs_dir.join("scan_results.json");
    let json = serde_json::to_string_pretty(res)?;
    std::fs::write(&path, json)?;
    tracing::info!("scan: results -> {}", path.display());
    Ok(())
}
