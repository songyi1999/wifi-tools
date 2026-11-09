//! Configuration: config.toml load/save with defaults.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetsCfg {
    #[serde(default = "default_targets")]
    pub list: Vec<String>,
}

fn default_targets() -> Vec<String> {
    vec!["318".into(), "tp3-204".into(), "huawei-303".into()]
}

impl Default for TargetsCfg {
    fn default() -> Self {
        Self { list: default_targets() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCfg {
    #[serde(default = "default_scan_duration")]
    pub duration_sec: u64,
    #[serde(default = "default_scan_interval")]
    pub interval_sec: u64,
    #[serde(default = "default_disconnect_first")]
    pub disconnect_first: bool,
}

impl Default for ScanCfg {
    fn default() -> Self {
        Self {
            duration_sec: default_scan_duration(),
            interval_sec: default_scan_interval(),
            disconnect_first: default_disconnect_first(),
        }
    }
}

fn default_scan_duration() -> u64 {
    90
}
fn default_scan_interval() -> u64 {
    4
}
fn default_disconnect_first() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureCfg {
    #[serde(default = "default_capture_duration")]
    pub duration_sec: u64,
    #[serde(default = "default_interface")]
    pub interface: String,
}

fn default_capture_duration() -> u64 {
    120
}
fn default_interface() -> String {
    "WLAN".into()
}

impl Default for CaptureCfg {
    fn default() -> Self {
        Self {
            duration_sec: default_capture_duration(),
            interface: default_interface(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackCfg {
    #[serde(default = "default_acng_bin")]
    pub acng_bin: PathBuf,
    /// Primary dictionary (checked first if it exists)
    #[serde(default = "default_dict")]
    pub dict: PathBuf,
    /// Extra dictionaries: every *.txt|*.dic|*.lst in this directory
    #[serde(default = "default_dicts_dir")]
    pub dicts_dir: PathBuf,
    /// Legacy fallback (mini_dict)
    #[serde(default = "default_dict_fallback")]
    pub dict_fallback: PathBuf,
    /// Use the built-in pattern dictionary (dates/pinyin/common) via stdin
    #[serde(default = "default_use_patterns")]
    pub use_patterns: bool,
    /// Include the full 8-digit numeric space (100M candidates, slow)
    #[serde(default = "default_full8")]
    pub full8: bool,
    #[serde(default = "default_crack_timeout")]
    pub timeout_sec: u64,
}

fn default_acng_bin() -> PathBuf {
    PathBuf::from(r"C:\Users\songyi\.ssh\wifi_crack\acng_extracted\aircrack-ng-1.7-win\bin")
}
fn default_dict() -> PathBuf {
    PathBuf::from(r"E:\project\wifi-toolkit\dicts\rockyou.txt")
}
fn default_dicts_dir() -> PathBuf {
    PathBuf::from(r"E:\project\wifi-toolkit\dicts")
}
fn default_dict_fallback() -> PathBuf {
    PathBuf::from(r"C:\Users\songyi\.ssh\wifi_crack\tools\mini_dict.txt")
}
fn default_use_patterns() -> bool {
    true
}
fn default_full8() -> bool {
    false
}
fn default_crack_timeout() -> u64 {
    1800
}

impl Default for CrackCfg {
    fn default() -> Self {
        Self {
            acng_bin: default_acng_bin(),
            dict: default_dict(),
            dicts_dir: default_dicts_dir(),
            dict_fallback: default_dict_fallback(),
            use_patterns: default_use_patterns(),
            full8: default_full8(),
            timeout_sec: default_crack_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreCfg {
    /// Empty = remember current SSID before run.
    #[serde(default)]
    pub ssid: String,
}

impl Default for RestoreCfg {
    fn default() -> Self {
        Self { ssid: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslCfg {
    /// Kali WSL distro name
    #[serde(default = "default_wsl_distro")]
    pub distro: String,
    /// PixieDust attack timeout per target
    #[serde(default = "default_pixie_timeout")]
    pub pixie_timeout_sec: u64,
}

fn default_wsl_distro() -> String {
    "kali-linux".into()
}
fn default_pixie_timeout() -> u64 {
    90
}

impl Default for WslCfg {
    fn default() -> Self {
        Self { distro: default_wsl_distro(), pixie_timeout_sec: default_pixie_timeout() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub targets: TargetsCfg,
    #[serde(default)]
    pub scan: ScanCfg,
    #[serde(default)]
    pub capture: CaptureCfg,
    #[serde(default)]
    pub crack: CrackCfg,
    #[serde(default)]
    pub restore: RestoreCfg,
    #[serde(default)]
    pub wsl: WslCfg,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: TargetsCfg { list: default_targets() },
            scan: ScanCfg {
                duration_sec: default_scan_duration(),
                interval_sec: default_scan_interval(),
                disconnect_first: default_disconnect_first(),
            },
            capture: CaptureCfg {
                duration_sec: default_capture_duration(),
                interface: default_interface(),
            },
            crack: CrackCfg::default(),
            restore: RestoreCfg::default(),
            wsl: WslCfg::default(),
        }
    }
}

impl Config {
    /// All usable dictionaries in try order: primary dict, then every
    /// *.txt|*.dic|*.lst in dicts_dir (sorted), then the legacy fallback.
    pub fn effective_dicts(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        if self.crack.dict.exists() {
            out.push(self.crack.dict.clone());
        }
        if self.crack.dicts_dir.exists() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(&self.crack.dicts_dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("txt") | Some("dic") | Some("lst")
                    )
                })
                .collect();
            files.sort();
            for f in files {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
        if self.crack.dict_fallback.exists() && !out.contains(&self.crack.dict_fallback) {
            out.push(self.crack.dict_fallback.clone());
        }
        out
    }
}

/// Load config.toml from the given path (or next to exe / cwd).
pub fn load(path: Option<&Path>) -> Result<Config> {
    let p = resolve_config_path(path)?;
    if !p.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&p)
        .with_context(|| format!("reading {}", p.display()))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("parsing {}", p.display()))?;
    Ok(cfg)
}

/// Save config back to path.
pub fn save(cfg: &Config, path: &Path) -> Result<()> {
    let text = toml::to_string_pretty(cfg)?;
    std::fs::write(path, text)?;
    Ok(())
}

pub fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    // 1. config.toml next to the exe
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.toml");
            if p.exists() {
                return Ok(p);
            }
        }
    }
    // 2. cwd/config.toml (create there when saving)
    Ok(PathBuf::from("config.toml"))
}

/// Where result JSON files / logs go: <base>/logs
pub fn logs_dir() -> PathBuf {
    PathBuf::from("logs")
}

/// Ensure logs dir + caps subdir exist; return logs dir path.
pub fn ensure_logs_dir() -> PathBuf {
    let d = logs_dir();
    let _ = std::fs::create_dir_all(d.join("caps"));
    d
}
