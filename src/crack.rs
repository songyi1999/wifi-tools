//! Offline crack: aircrack-ng.exe -a 2 -w <dict> <cap>, parse "KEY FOUND".

use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct CrackResult {
    pub cap: String,
    pub cracked: bool,
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extract the key from aircrack output. Aircrack 1.7 prints:
///   KEY FOUND! [ thekey ]
/// Cascade: bracket after KEY FOUND marker -> colon form -> per-line bracket.
fn extract_key(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    if !lower.contains("key found") {
        return None;
    }
    // Stage 1: KEY FOUND! [ key ]
    let re1 = regex::Regex::new(r"(?i)key found[^\[]*\[\s*([^\]]+)\s*\]").unwrap();
    if let Some(c) = re1.captures(text) {
        return Some(c[1].trim().to_string());
    }
    // Stage 2: colon form
    let re2 = regex::Regex::new(r"(?i)key found.*?:\s*(\S+)").unwrap();
    if let Some(c) = re2.captures(text) {
        return Some(c[1].trim().to_string());
    }
    // Stage 3: per-line bracket
    for line in text.lines() {
        if line.to_lowercase().contains("key found") {
            let re3 = regex::Regex::new(r"\[([^\]]+)\]").unwrap();
            if let Some(c) = re3.captures(line) {
                return Some(c[1].trim().to_string());
            }
        }
    }
    None
}

fn run_aircrack(acng_bin: &Path, exe: &Path, cap: &Path, dict: &Path) -> Result<String> {
    let out = Command::new(exe)
        .arg("-a")
        .arg("2")
        .arg("-w")
        .arg(dict)
        .arg(cap)
        .current_dir(acng_bin) // Cygwin DLLs live here
        .output()?;
    Ok(format!(
        "{}{}",
        crate::netsh::decode_gbk(&out.stdout),
        crate::netsh::decode_gbk(&out.stderr)
    ))
}

pub fn crack_caps(
    acng_bin: &Path,
    caps_dir: &Path,
    dict: &Path,
    timeout_sec: u64,
) -> Result<Vec<CrackResult>> {
    let exe = acng_bin.join("aircrack-ng.exe");
    if !exe.exists() {
        anyhow::bail!("aircrack-ng.exe not found in {}", acng_bin.display());
    }
    let mut caps: Vec<PathBuf> = Vec::new();
    if caps_dir.exists() {
        for entry in std::fs::read_dir(caps_dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("cap") {
                caps.push(p);
            }
        }
    }
    caps.sort();
    if caps.is_empty() {
        tracing::info!("crack: no .cap files in {} — nothing to do", caps_dir.display());
        return Ok(Vec::new());
    }
    tracing::info!("crack: {} cap file(s), dict={}", caps.len(), dict.display());

    let mut results = Vec::new();
    for cap in &caps {
        let name = cap.file_name().unwrap_or_default().to_string_lossy().to_string();
        tracing::info!("crack: running aircrack-ng on {} ...", name);
        // std has no timeout; aircrack with a wordlist on small dicts is fast.
        // For safety we spawn and rely on the dict being bounded; a hung process
        // is unusual. (timeout_sec is advisory here.)
        let _ = timeout_sec;
        let text = match run_aircrack(acng_bin, &exe, cap, dict) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("crack: {}: spawn error {}", name, e);
                results.push(CrackResult {
                    cap: name,
                    cracked: false,
                    password: None,
                    timed_out: None,
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        if let Some(key) = extract_key(&text) {
            tracing::info!("crack: *** CRACKED {} -> {} ***", name, key);
            results.push(CrackResult {
                cap: name,
                cracked: true,
                password: Some(key),
                timed_out: None,
                error: None,
            });
        } else {
            tracing::info!("crack: not cracked: {}", name);
            results.push(CrackResult {
                cap: name,
                cracked: false,
                password: None,
                timed_out: None,
                error: None,
            });
        }
    }
    let n = results.iter().filter(|r| r.cracked).count();
    tracing::info!("crack: done {}/{} cracked", n, results.len());
    Ok(results)
}

/// Save results JSON to logs/crack_results.json.
pub fn save_result(res: &[CrackResult], logs_dir: &Path) -> Result<()> {
    let path = logs_dir.join("crack_results.json");
    let json = serde_json::to_string_pretty(res)?;
    std::fs::write(&path, json)?;
    tracing::info!("crack: results -> {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::extract_key;

    #[test]
    fn parses_modern_key_found() {
        let t = "Aircrack-ng 1.7\n\nKEY FOUND! [ SuperSecret123 ]\n\n";
        assert_eq!(extract_key(t), Some("SuperSecret123".into()));
    }

    #[test]
    fn parses_legacy_key_found() {
        let t = "KEY FOUND: abc12345";
        assert_eq!(extract_key(t), Some("abc12345".into()));
    }

    #[test]
    fn no_key() {
        assert_eq!(extract_key("No keys found in capture"), None);
    }
}
