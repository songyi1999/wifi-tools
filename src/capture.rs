//! airodump-ng capture per target. Note: on Windows airodump only supports
//! AirPcap USB hardware; the built-in Intel AX201 reports "not supported".

use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::CaptureCfg;

#[derive(Debug, Clone, Serialize)]
pub struct CaptureResult {
    pub target: String,
    pub supported: bool,
    pub output: String,
}

fn run_airodump(acng_bin: &Path, iface: &str, cap_file: &Path, duration: u64) -> Result<String> {
    // aircrack-ng 1.7 Windows build is Cygwin-based: must run under cmd with cwd set.
    let cmd = format!(
        "cd /d \"{}\" && timeout {} airodump-ng.exe -i {} -w \"{}\"",
        acng_bin.display(),
        duration,
        iface,
        cap_file.display()
    );
    let out = Command::new("cmd")
        .args(["/c", &cmd])
        .output()?;
    let text = crate::netsh::decode_gbk(&out.stdout);
    let err = crate::netsh::decode_gbk(&out.stderr);
    Ok(format!("{}{}", text, err))
}

pub fn capture(cfg: &CaptureCfg, acng_bin: &Path, targets: &[String], caps_dir: &Path) -> Result<Vec<CaptureResult>> {
    let mut results = Vec::new();
    for target in targets {
        // Sanitize target for filename
        let safe: String = target
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let cap_file = caps_dir.join(&safe);
        tracing::info!("capture: {} ({}s)...", target, cfg.duration_sec);
        let output = match run_airodump(acng_bin, &cfg.interface, &cap_file, cfg.duration_sec) {
            Ok(o) => o,
            Err(e) => format!("spawn error: {}", e),
        };
        let supported = !output.to_lowercase().contains("not supported");
        if supported {
            tracing::info!("capture: {}: ran, output: {}", target, &output[..output.len().min(200)]);
        } else {
            tracing::warn!(
                "capture: {}: adapter not supported (expected on Intel AX201 without AirPcap)",
                target
            );
        }
        results.push(CaptureResult {
            target: target.clone(),
            supported,
            output: output.chars().take(500).collect(),
        });
    }
    Ok(results)
}

/// Save results JSON to logs/capture_results.json.
pub fn save_result(res: &[CaptureResult], logs_dir: &Path) -> Result<()> {
    let path = logs_dir.join("capture_results.json");
    let json = serde_json::to_string_pretty(res)?;
    std::fs::write(&path, json)?;
    tracing::info!("capture: results -> {}", path.display());
    Ok(())
}

/// Where .cap files go.
pub fn caps_dir(logs_dir: &Path) -> PathBuf {
    let d = logs_dir.join("caps");
    let _ = std::fs::create_dir_all(&d);
    d
}
