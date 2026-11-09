//! Pipeline: full flow with guaranteed restore.
//! record SSID -> scan -> capture -> crack -> [RestoreGuard Drop] restore.

use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::netsh;
use crate::restore::RestoreGuard;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PipelineSummary {
    pub original_ssid: String,
    pub final_ssid: Option<String>,
    pub restored: bool,
    pub elapsed_sec: u64,
    pub scan_ssids: Option<usize>,
    pub crack_found: Vec<String>,
}

/// Events a worker can emit (used by the GUI to show live progress).
pub type EventTx = std::sync::mpsc::Sender<String>;

pub fn emit(_tx: Option<&EventTx>, msg: &str) {
    // The web UI receives everything through the tracing mirror layer.
    tracing::info!("{}", msg);
}

/// Run the full pipeline. `logs_dir` receives all JSON results.
/// The restore runs via RestoreGuard no matter what (panics included).
pub fn run_full(cfg: &Config, logs_dir: &Path, tx: Option<&EventTx>) -> Result<PipelineSummary> {
    let t_start = std::time::Instant::now();

    // Step 0: remember current network
    let iface = netsh::show_interface()?;
    let original = cfg
        .restore
        .ssid
        .is_empty()
        .then(|| iface.ssid.clone().unwrap_or_else(|| "Redmi_D1B4".into()))
        .unwrap_or_else(|| cfg.restore.ssid.clone());
    emit(
        tx,
        &format!("[step 0] current network: {:?} (state {:?}) — will restore to it",
            iface.ssid, iface.state),
    );

    // The guard guarantees restoration even on panic/early return.
    let mut guard = RestoreGuard::new(original.clone());
    let mut summary = PipelineSummary {
        original_ssid: original.clone(),
        ..Default::default()
    };

    let result = (|| -> Result<()> {
        // Step 1: scan
        emit(tx, "[step 1/4] scan ...");
        let scan_res = crate::scan::scan(&cfg.scan, Some(&original))?;
        summary.scan_ssids = Some(scan_res.total_ssids);
        crate::scan::save_result(&scan_res, &logs_dir)?;

        // Step 2: capture
        emit(tx, "[step 2/4] airodump capture ...");
        let caps_dir = crate::capture::caps_dir(&logs_dir);
        let cap_res = crate::capture::capture(
            &cfg.capture,
            &cfg.crack.acng_bin,
            &cfg.targets.list,
            &caps_dir,
        )?;
        crate::capture::save_result(&cap_res, &logs_dir)?;

        // Step 4: crack
        emit(tx, "[step 3/4] offline crack ...");
        let dicts = cfg.effective_dicts();
        if !dicts.is_empty() || cfg.crack.use_patterns {
            let crack_res = crate::crack::crack_caps(
                &cfg.crack.acng_bin,
                &caps_dir,
                &cfg.crack,
                &dicts,
                tx,
            )?;
            for r in &crack_res {
                if r.cracked {
                    summary
                        .crack_found
                        .push(format!("{}={}", r.cap, r.password.clone().unwrap_or_default()));
                }
            }
            crate::crack::save_result(&crack_res, &logs_dir)?;
        } else {
            emit(tx, "[step 3/4] no dictionaries found — skipping crack");
        }
        Ok(())
    })();

    if let Err(e) = result {
        emit(tx, &format!("[pipeline] error: {} (restoring anyway)", e));
    }

    // Explicit restore while we can still log the outcome.
    emit(tx, "[step 4/4] restoring connection ...");
    let ok = crate::restore::reconnect(&original)?;
    tracing::info!("explicit restore result: {}", ok);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let final_iface = netsh::show_interface()?;
    summary.final_ssid = final_iface.ssid.clone();
    summary.restored = final_iface.ssid.as_deref() == Some(original.as_str());
    summary.elapsed_sec = t_start.elapsed().as_secs();

    emit(
        tx,
        &format!(
            "[pipeline] done in {}s — original={:?} final={:?} restored={}",
            summary.elapsed_sec, summary.original_ssid, summary.final_ssid, summary.restored
        ),
    );

    // Mark guard done so Drop doesn't reconnect twice.
    guard.done = true;
    drop(guard);

    // summary.json
    let json = serde_json::to_string_pretty(&summary)?;
    let _ = std::fs::write(logs_dir.join("summary.json"), json);

    Ok(summary)
}

/// Export saved profile passwords -> logs/passwords_export.txt.
pub fn export_passwords(logs_dir: &Path) -> Result<PathBuf> {
    let pairs = netsh::export_profiles()?;
    let mut text = String::new();
    for (name, pw) in &pairs {
        text.push_str(&format!("{} | {}\n", name, pw));
    }
    let path = logs_dir.join("passwords_export.txt");
    std::fs::write(&path, text)?;
    tracing::info!("export: {} profiles -> {}", pairs.len(), path.display());
    Ok(path)
}
