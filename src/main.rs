//! wifi-toolkit: WiFi scan / WPS probe / capture / crack with auto-restore.

mod capture;
mod config;
mod crack;
mod logging;
mod netsh;
mod pipeline;
mod restore;
mod scan;
mod ui;
mod wlanapi;
mod wps;

use clap::{Parser, Subcommand};
use std::path::Path;

#[derive(Parser)]
#[command(name = "wifi-toolkit", version, about = "WiFi toolkit: scan / WPS / capture / crack (auto-restore)")]
struct Cli {
    /// Path to config.toml (default: next to exe or cwd)
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the GUI (default when no subcommand)
    Gui,
    /// Full pipeline unattended: scan -> wps -> capture -> crack -> restore
    Run,
    /// Quick scan: trigger active scans + read refreshed list (never disconnects)
    Nets,
    /// Multi-round scan (writes scan_results.json)
    Scan,
    /// WPS PIN probe against configured targets
    Wps,
    /// airodump-ng capture per target
    Capture,
    /// Offline crack of logs/caps/*.cap, or a specific cap with `cap` (+`dict`, "-" = patterns)
    Crack { cap: Option<std::path::PathBuf>, dict: Option<std::path::PathBuf> },
    /// Manage dictionaries: list | update (download top-1M + password.lst)
    Dict { #[arg(default_value = "list")] action: String },
    /// Reconnect to a saved profile SSID (8 retries)
    Reconnect { ssid: String },
    /// Export all saved profile passwords to logs/passwords_export.txt
    ExportPasswords,
}

fn main() {
    let cli = Cli::parse();
    let logs_dir = config::ensure_logs_dir();
    // Keep the logging guard alive for the whole process.
    let _guard = logging::init(&logs_dir);

    let cfg = match config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {:#}", e);
            std::process::exit(1);
        }
    };

    let code = match cli.command.unwrap_or(Command::Gui) {
        Command::Gui => run_gui(cfg),
        Command::Run => run_pipeline(cfg),
        Command::Nets => run_nets(),
        Command::Scan => run_scan(cfg),
        Command::Wps => run_wps(cfg),
        Command::Capture => run_capture(cfg),
        Command::Crack { cap, dict } => run_crack(cfg, cap, dict),
        Command::Dict { action } => run_dict(cfg, &action),
        Command::Reconnect { ssid } => run_reconnect(&ssid),
        Command::ExportPasswords => run_export(),
    };
    std::process::exit(code);
}

fn run_gui(cfg: config::Config) -> i32 {
    match ui::start(cfg) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("GUI failed: {:#}", e);
            1
        }
    }
}

fn run_pipeline(cfg: config::Config) -> i32 {
    let logs_dir = config::ensure_logs_dir();
    match pipeline::run_full(&cfg, &logs_dir, None) {
        Ok(s) => {
            println!(
                "done in {}s — restored: {} (original {:?}, final {:?})",
                s.elapsed_sec, s.restored, s.original_ssid, s.final_ssid
            );
            if s.restored { 0 } else { 2 }
        }
        Err(e) => {
            tracing::error!("pipeline failed: {:#}", e);
            1
        }
    }
}

fn run_nets() -> i32 {
    println!("quick scan: 4 rounds, WlanScan trigger each round (~15s, no disconnect)...");
    match scan::quick_scan(4, std::time::Duration::from_secs(3), None) {
        Ok(nets) => {
            let mut nets = nets;
            nets.sort_by_key(|n| std::cmp::Reverse(n.signal.unwrap_or(0)));
            println!("\n{} SSID(s)（按信号强度排序）:", nets.len());
            for n in &nets {
                let ssid = if n.ssid == "(empty)" { "(隐藏网络)" } else { &n.ssid };
                println!(
                    "  {:24} 信号={:<4} 频道={:<4} {}  bssid={}",
                    ssid,
                    n.signal.map(|s| format!("{}%", s)).unwrap_or_else(|| "?".into()),
                    n.channel.as_deref().unwrap_or("?"),
                    n.auth.as_deref().unwrap_or(""),
                    n.bssid.as_deref().unwrap_or("?")
                );
            }
            if nets.len() <= 1 {
                println!("\nNOTE: only the current AP visible — WlanScan trigger may have failed; check log warnings.");
                2
            } else {
                0
            }
        }
        Err(e) => {
            tracing::error!("nets failed: {:#}", e);
            1
        }
    }
}

fn run_scan(cfg: config::Config) -> i32 {
    let logs_dir = config::ensure_logs_dir();
    let restore_to = cfg.scan.disconnect_first.then(|| {
        netsh::show_interface().ok().and_then(|i| i.ssid).unwrap_or_default()
    });
    match scan::scan(&cfg.scan, restore_to.as_deref()) {
        Ok(res) => {
            if let Err(e) = scan::save_result(&res, &logs_dir) {
                tracing::error!("saving scan results: {:#}", e);
            }
            println!("scanned {} SSIDs in {} rounds", res.total_ssids, res.rounds);
            0
        }
        Err(e) => {
            tracing::error!("scan failed: {:#}", e);
            1
        }
    }
}

fn run_wps(cfg: config::Config) -> i32 {
    let logs_dir = config::ensure_logs_dir();
    match wps::probe(&cfg.wps, &cfg.targets.list) {
        Ok(res) => {
            if let Err(e) = wps::save_result(&res, &logs_dir) {
                tracing::error!("saving wps results: {:#}", e);
            }
            0
        }
        Err(e) => {
            tracing::error!("wps failed: {:#}", e);
            1
        }
    }
}

fn run_capture(cfg: config::Config) -> i32 {
    let logs_dir = config::ensure_logs_dir();
    let caps_dir = capture::caps_dir(&logs_dir);
    match capture::capture(&cfg.capture, &cfg.crack.acng_bin, &cfg.targets.list, &caps_dir) {
        Ok(res) => {
            if let Err(e) = capture::save_result(&res, &logs_dir) {
                tracing::error!("saving capture results: {:#}", e);
            }
            0
        }
        Err(e) => {
            tracing::error!("capture failed: {:#}", e);
            1
        }
    }
}

fn run_crack(cfg: config::Config, cap: Option<std::path::PathBuf>, dict: Option<std::path::PathBuf>) -> i32 {
    let logs_dir = config::ensure_logs_dir();
    let acng = cfg.crack.acng_bin.clone();

    // Single cap mode: `crack <cap> [dict]`, dict "-" = built-in patterns
    if let Some(cap) = cap {
        let name = cap.file_name().unwrap_or_default().to_string_lossy().to_string();
        let res = match dict.as_deref() {
            Some(p) if p == Path::new("-") => crack::crack_one_patterns(
                &acng,
                &cap,
                cfg.crack.full8,
                None,
                std::time::Duration::from_secs(cfg.crack.timeout_sec),
            ),
            Some(d) => crack::crack_one_file(
                &acng,
                &cap,
                d,
                std::time::Duration::from_secs(cfg.crack.timeout_sec),
            ),
            None => {
                let dicts = cfg.effective_dicts();
                if dicts.is_empty() {
                    tracing::error!("no dictionaries available (see `dict update`)");
                    return 1;
                }
                let to = std::time::Duration::from_secs(cfg.crack.timeout_sec);
                let mut res = match crack::crack_one_patterns(&acng, &cap, cfg.crack.full8, None, to) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("crack failed: {:#}", e);
                        return 1;
                    }
                };
                if !res.cracked {
                    for d in &dicts {
                        res = match crack::crack_one_file(&acng, &cap, d, to) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::warn!("dict {} failed: {:#}", d.display(), e);
                                continue;
                            }
                        };
                        if res.cracked {
                            break;
                        }
                    }
                }
                Ok(res)
            }
        };
        return match res {
            Ok(r) => {
                println!(
                    "{}: {} ({})",
                    name,
                    if r.cracked {
                        format!("CRACKED = {:?}", r.password)
                    } else {
                        "not cracked".into()
                    },
                    r.source.as_deref().unwrap_or("?")
                );
                if r.cracked { 0 } else { 2 }
            }
            Err(e) => {
                tracing::error!("crack failed: {:#}", e);
                1
            }
        };
    }

    // Default: all caps in logs/caps
    let caps_dir = capture::caps_dir(&logs_dir);
    let dicts = cfg.effective_dicts();
    if dicts.is_empty() {
        tracing::error!("no dictionaries available — run `wifi-toolkit dict update` first");
        return 1;
    }
    println!(
        "cracking all caps in {} with {} dict(s){}...",
        caps_dir.display(),
        dicts.len(),
        if cfg.crack.use_patterns { " + patterns" } else { "" }
    );
    match crack::crack_caps(&acng, &caps_dir, &cfg.crack, &dicts, None) {
        Ok(res) => {
            if let Err(e) = crack::save_result(&res, &logs_dir) {
                tracing::error!("saving crack results: {:#}", e);
            }
            for r in &res {
                println!(
                    "  {}: {} ({})",
                    r.cap,
                    if r.cracked {
                        format!("CRACKED = {:?}", r.password)
                    } else {
                        "not cracked".into()
                    },
                    r.source.as_deref().unwrap_or("?")
                );
            }
            0
        }
        Err(e) => {
            tracing::error!("crack failed: {:#}", e);
            1
        }
    }
}

/// Download `url` to `dest` trying each mirror prefix; returns the one that worked.
fn curl_download(dest: &Path, url: &str, min_bytes: u64) -> anyhow::Result<()> {
    let mirrors = [
        String::new(),
        "https://gh-proxy.com/".into(),
        "https://ghproxy.net/".into(),
    ];
    for m in &mirrors {
        let full = format!("{}{}", m, url);
        let status = std::process::Command::new("curl")
            .args(["-sfL", "--retry", "2", "--max-time", "1200", "-o"])
            .arg(dest)
            .arg(&full)
            .status();
        if let Ok(s) = status {
            if s.success() {
                if let Ok(md) = std::fs::metadata(dest) {
                    if md.len() >= min_bytes {
                        return Ok(());
                    }
                }
            }
        }
    }
    anyhow::bail!("all mirrors failed for {}", url)
}

fn run_dict(cfg: config::Config, action: &str) -> i32 {
    let dir = cfg.crack.dicts_dir.clone();
    match action {
        "update" => {
            let _ = std::fs::create_dir_all(&dir);
            let mut code = 0;
            // top-1M (xato) from SecLists, via jsdelivr first (GitHub raw often blocked)
            let xato = dir.join("xato100w.txt");
            if !xato.exists() {
                println!("downloading xato top-1M (8.5MB)...");
                let ok = (|| -> anyhow::Result<()> {
                    for u in [
                        "https://fastly.jsdelivr.net/gh/danielmiessler/SecLists@master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
                        "https://gcore.jsdelivr.net/gh/danielmiessler/SecLists@master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
                        "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
                    ] {
                        let s = std::process::Command::new("curl")
                            .args(["-sfL", "--retry", "2", "--max-time", "300", "-o"])
                            .arg(&xato)
                            .arg(u)
                            .status();
                        if matches!(s, Ok(st) if st.success()) && xato.metadata().map(|m| m.len() > 1_000_000).unwrap_or(false) {
                            return Ok(());
                        }
                    }
                    anyhow::bail!("xato download failed")
                })();
                if ok.is_err() {
                    code = 1;
                }
            }
            // rockyou (134MB) via release mirrors
            let rock = dir.join("rockyou.txt");
            if !rock.exists() {
                println!("downloading rockyou.txt (134MB, may take a while)...");
                if curl_download(
                    &rock,
                    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
                    100_000_000,
                )
                .is_err()
                {
                    code = 1;
                }
            }
            println!("done. dictionaries in {}:", dir.display());
            list_dicts(&dir);
            code
        }
        _ => {
            list_dicts(&dir);
            0
        }
    }
}

fn list_dicts(dir: &Path) {
    if !dir.exists() {
        println!("  (dicts dir {} does not exist)", dir.display());
        return;
    }
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if matches!(
            p.extension().and_then(|x| x.to_str()),
            Some("txt") | Some("dic") | Some("lst")
        ) {
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            let lines = count_lines(&p);
            println!(
                "  {:30} {:>10.1} MB  {} lines",
                p.file_name().unwrap_or_default().to_string_lossy(),
                size as f64 / 1024.0 / 1024.0,
                lines
            );
        }
    }
}

fn count_lines(p: &Path) -> String {
    match std::fs::File::open(p) {
        Ok(f) => {
            use std::io::{BufRead, BufReader};
            let n = BufReader::new(f).lines().count();
            format!("{}", n)
        }
        Err(_) => "?".into(),
    }
}

fn run_reconnect(ssid: &str) -> i32 {
    match restore::reconnect(ssid) {
        Ok(true) => {
            println!("connected to {}", ssid);
            0
        }
        Ok(false) => {
            println!("FAILED to connect to {}", ssid);
            1
        }
        Err(e) => {
            tracing::error!("reconnect failed: {:#}", e);
            1
        }
    }
}

fn run_export() -> i32 {
    let logs_dir = config::ensure_logs_dir();
    match pipeline::export_passwords(&logs_dir) {
        Ok(p) => {
            println!("exported to {}", p.display());
            0
        }
        Err(e) => {
            tracing::error!("export failed: {:#}", e);
            1
        }
    }
}
