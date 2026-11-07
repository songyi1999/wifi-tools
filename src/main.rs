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
mod wps;

use clap::{Parser, Subcommand};

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
    /// Multi-round scan (writes scan_results.json)
    Scan,
    /// WPS PIN probe against configured targets
    Wps,
    /// airodump-ng capture per target
    Capture,
    /// aircrack-ng offline crack of logs/caps/*.cap
    Crack,
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
        Command::Scan => run_scan(cfg),
        Command::Wps => run_wps(cfg),
        Command::Capture => run_capture(cfg),
        Command::Crack => run_crack(cfg),
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

fn run_crack(cfg: config::Config) -> i32 {
    let logs_dir = config::ensure_logs_dir();
    let caps_dir = capture::caps_dir(&logs_dir);
    match cfg.effective_dict() {
        Some(dict) => match crack::crack_caps(&cfg.crack.acng_bin, &caps_dir, &dict, cfg.crack.timeout_sec) {
            Ok(res) => {
                if let Err(e) = crack::save_result(&res, &logs_dir) {
                    tracing::error!("saving crack results: {:#}", e);
                }
                0
            }
            Err(e) => {
                tracing::error!("crack failed: {:#}", e);
                1
            }
        },
        None => {
            tracing::error!("no dictionary found (checked {:?} and {:?})", cfg.crack.dict, cfg.crack.dict_fallback);
            1
        }
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
