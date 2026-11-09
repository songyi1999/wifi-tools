//! Capture sessions: each batch (or ad-hoc) capture lands in its own
//! timestamped directory with a manifest recording which caps actually
//! contain a handshake — so cracking can target "this run" instead of
//! every cap ever collected.

use anyhow::{bail, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize, Deserialize, Clone)]
pub struct CapEntry {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub essid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Some(true) = handshake captured, Some(false) = beacons only,
    /// None = not yet checked.
    pub handshake: Option<bool>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Manifest {
    #[serde(default)]
    pub caps: Vec<CapEntry>,
}

#[derive(Serialize, Clone)]
pub struct SessionInfo {
    /// directory name ("" = loose caps in logs/caps root from older runs)
    pub dir: String,
    pub caps: usize,
    pub handshakes: usize,
    pub unknown: usize,
}

pub fn new_session_dir(root: &Path) -> PathBuf {
    let name = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let dir = root.join(&name);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.json")
}

pub fn load_manifest(dir: &Path) -> Manifest {
    std::fs::read_to_string(manifest_path(dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_manifest(dir: &Path, m: &Manifest) -> Result<()> {
    let json = serde_json::to_string_pretty(m)?;
    std::fs::write(manifest_path(dir), json)?;
    Ok(())
}

/// Record a produced cap in the session manifest (handshake not yet checked).
pub fn record_cap(
    dir: &Path,
    file: &str,
    essid: Option<&str>,
    bssid: Option<&str>,
    channel: Option<&str>,
) -> Result<()> {
    let mut m = load_manifest(dir);
    if m.caps.iter().any(|c| c.file == file) {
        return Ok(());
    }
    m.caps.push(CapEntry {
        file: file.to_string(),
        essid: essid.map(|s| s.to_string()),
        bssid: bssid.map(|s| s.to_string()),
        channel: channel.map(|s| s.to_string()),
        handshake: None,
    });
    save_manifest(dir, &m)
}

/// Run aircrack-ng without a wordlist and read the handshake count from the
/// targets table ("WPA (1 handshake, with IV)").
pub fn check_handshake(acng_bin: &Path, cap: &Path) -> Option<bool> {
    let exe = acng_bin.join("aircrack-ng.exe");
    if !exe.exists() {
        return None;
    }
    let cap_abs = if cap.is_absolute() {
        cap.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(cap)
    };
    let out = Command::new(&exe).arg(&cap_abs).current_dir(acng_bin).output().ok()?;
    let text = format!(
        "{}{}",
        crate::netsh::decode_gbk(&out.stdout),
        crate::netsh::decode_gbk(&out.stderr)
    );
    let re = regex::Regex::new(r"(\d+)\s+handshake").ok()?;
    let n: u32 = re
        .captures_iter(&text)
        .filter_map(|c| c[1].parse::<u32>().ok())
        .sum::<u32>();
    Some(n > 0)
}

/// Fill in unknown handshake flags for every entry in the manifest.
pub fn finalize_manifest(dir: &Path, acng_bin: &Path) -> Result<(usize, usize)> {
    let mut m = load_manifest(dir);
    let mut with_hs = 0usize;
    let mut without = 0usize;
    for entry in m.caps.iter_mut() {
        let cap_path = dir.join(&entry.file);
        if !cap_path.exists() {
            entry.handshake = Some(false);
        } else if entry.handshake.is_none() {
            entry.handshake = check_handshake(acng_bin, &cap_path);
        }
        match entry.handshake {
            Some(true) => with_hs += 1,
            Some(false) => without += 1,
            None => {}
        }
    }
    save_manifest(dir, &m)?;
    Ok((with_hs, without))
}

/// List all sessions (subdirectories of caps root with caps or a manifest),
/// plus one pseudo-session for loose caps sitting directly in the root.
pub fn list_sessions(root: &Path) -> Vec<SessionInfo> {
    let mut out: Vec<SessionInfo> = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for d in dirs {
        let caps: Vec<PathBuf> = std::fs::read_dir(&d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("cap"))
            .collect();
        if caps.is_empty() {
            continue;
        }
        let m = load_manifest(&d);
        let mut handshakes = 0usize;
        let mut unknown = 0usize;
        for c in &m.caps {
            match c.handshake {
                Some(true) => handshakes += 1,
                Some(false) => {}
                None => unknown += 1,
            }
        }
        out.push(SessionInfo {
            dir: d.file_name().unwrap_or_default().to_string_lossy().to_string(),
            caps: caps.len(),
            handshakes,
            unknown,
        });
    }
    // loose caps directly in root (pre-session era)
    let loose: Vec<PathBuf> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("cap"))
        .collect();
    if !loose.is_empty() {
        out.push(SessionInfo {
            dir: String::new(),
            caps: loose.len(),
            handshakes: 0,
            unknown: loose.len(),
        });
    }
    out.reverse(); // newest first (timestamped names sort lexicographically)
    out
}

/// Resolve a crack scope to concrete cap files.
/// scope: "latest" (newest session) | "all" | a session directory name.
/// Caps known to have no handshake are skipped; unknown ones are checked
/// (and the manifest updated) unless acng_bin is None.
pub fn scope_caps(root: &Path, scope: &str, acng_bin: Option<&Path>) -> Result<(Vec<PathBuf>, usize, String)> {
    let sessions = list_sessions(root);
    if sessions.is_empty() {
        bail!("没有任何抓包文件（logs/caps/ 为空）");
    }
    let chosen: String = match scope {
        "latest" => sessions
            .iter()
            .map(|s| s.dir.clone())
            .find(|d| !d.is_empty())
            .unwrap_or_default(),
        "all" => String::new(),
        name => {
            if sessions.iter().any(|s| s.dir == name) {
                name.to_string()
            } else {
                sessions
                    .iter()
                    .map(|s| s.dir.clone())
                    .find(|d| !d.is_empty())
                    .unwrap_or_default()
            }
        }
    };
    let label = if chosen.is_empty() { "全部".into() } else { chosen.clone() };

    let mut files: Vec<PathBuf> = Vec::new();
    let mut skipped = 0usize;
    for s in &sessions {
        if !chosen.is_empty() && s.dir != chosen {
            continue;
        }
        let sdir = if s.dir.is_empty() { root.to_path_buf() } else { root.join(&s.dir) };
        let m = load_manifest(&sdir);
        for entry in &m.caps {
            let p = sdir.join(&entry.file);
            if !p.exists() {
                continue;
            }
            match entry.handshake {
                Some(false) => {
                    skipped += 1;
                }
                Some(true) => files.push(p),
                None => {
                    // unknown: check now when we can
                    let hs = acng_bin.and_then(|a| check_handshake(a, &p));
                    match hs {
                        Some(true) => files.push(p),
                        Some(false) => skipped += 1,
                        None => files.push(p), // can't tell — crack anyway
                    }
                }
            }
        }
        if !chosen.is_empty() {
            break;
        }
    }
    files.sort();
    files.dedup();
    Ok((files, skipped, label))
}

// ── PixieDust hit persistence ───────────────────────────────────────────────

pub fn hits_path(logs_dir: &Path) -> PathBuf {
    logs_dir.join("hits.json")
}

/// Load all recorded hits (newest first).
pub fn load_hits(logs_dir: &Path) -> Vec<crate::wslattack::PixieOut> {
    std::fs::read_to_string(hits_path(logs_dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Dedup by BSSID (newest wins), persist JSON + a human-readable txt.
pub fn record_hit(logs_dir: &Path, mut hit: crate::wslattack::PixieOut) -> Result<()> {
    if hit.time.is_empty() {
        hit.time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    }
    let mut hits = load_hits(logs_dir);
    hits.retain(|h| h.bssid != hit.bssid);
    hits.insert(0, hit);
    save_hits(logs_dir, &hits)
}

pub fn save_hits(logs_dir: &Path, hits: &[crate::wslattack::PixieOut]) -> Result<()> {
    std::fs::create_dir_all(logs_dir)?;
    let json = serde_json::to_string_pretty(hits)?;
    std::fs::write(hits_path(logs_dir), json)?;

    let mut txt = String::from("PixieDust 命中记录\n============\n");
    for h in hits {
        txt.push_str(&format!(
            "\n[{}] {} ({})\n  PIN = {}\n  PSK = {}\n",
            h.time,
            h.essid.as_deref().unwrap_or("(未知SSID)"),
            h.bssid,
            h.pin.as_deref().unwrap_or("(无)"),
            h.psk.as_deref().unwrap_or("(无)")
        ));
    }
    std::fs::write(logs_dir.join("hits.txt"), txt)?;
    Ok(())
}
