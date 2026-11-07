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

/// Trigger an active scan (WlanScan), wait for the sweep, then read the refreshed list.
/// This mirrors what Windows does when you open the WiFi flyout.
pub fn flyout_refresh(wait_sec: u64) -> Result<Vec<netsh::NetworkInfo>> {
    match crate::wlanapi::trigger_scan_all() {
        Ok(n) => tracing::info!("scan: WlanScan triggered on {} interface(s)", n),
        Err(e) => tracing::warn!("scan: WlanScan unavailable ({}); reading cached list", e),
    }
    std::thread::sleep(Duration::from_secs(wait_sec.max(2)));
    netsh::show_networks()
}

/// Insert or strengthen: keep the entry with the highest observed signal.
fn upsert_strongest(all: &mut Vec<netsh::NetworkInfo>, n: netsh::NetworkInfo) {
    if let Some(old) = all.iter_mut().find(|x| x.ssid == n.ssid) {
        if n.signal.unwrap_or(0) > old.signal.unwrap_or(0) {
            *old = n;
        }
        return;
    }
    all.push(n);
}

/// Multi-round quick scan with active-scan triggers; accumulates unique SSIDs.
/// Never disconnects — safe to run while connected.
pub fn quick_scan(
    rounds: u32,
    interval: Duration,
    tx: Option<&crate::pipeline::EventTx>,
) -> Result<Vec<netsh::NetworkInfo>> {
    let mut all: Vec<netsh::NetworkInfo> = Vec::new();
    for r in 0..rounds {
        if let Err(e) = crate::wlanapi::trigger_scan_all() {
            tracing::warn!("scan: WlanScan trigger failed: {:#}", e);
        }
        std::thread::sleep(interval);
        match netsh::show_networks() {
            Ok(nets) => {
                let before = all.len();
                for n in nets {
                    upsert_strongest(&mut all, n);
                }
                let msg = format!(
                    "quick-scan: round {}/{} -> +{} new (total {})",
                    r + 1,
                    rounds,
                    all.len() - before,
                    all.len()
                );
                tracing::info!("{}", msg);
                if let Some(tx) = tx {
                    let _ = tx.send(msg);
                }
            }
            Err(e) => tracing::warn!("scan: round {}: {}", r + 1, e),
        }
    }
    Ok(all)
}

/// Run deep scan. If `disconnect_first`, disconnect then reconnect afterwards via `restore_to`.
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
        // Trigger an active sweep every ~3 rounds so the cache keeps refreshing.
        if rounds % 3 == 0 {
            let _ = crate::wlanapi::trigger_scan_all();
        }
        match netsh::show_networks() {
            Ok(nets) => {
                for n in nets {
                    // Keep the strongest observation per SSID
                    match seen.get_mut(&n.ssid) {
                        Some(old) => {
                            if n.signal.unwrap_or(0) > old.signal.unwrap_or(0) {
                                *old = n;
                            }
                        }
                        None => {
                            seen.insert(n.ssid.clone(), n);
                        }
                    }
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
