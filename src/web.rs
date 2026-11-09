//! Web UI: axum server on 127.0.0.1 (random port) + wry webview window.
//! The WebView2 renderer bypasses the Intel OpenGL stride artifact entirely.
//! Worker tasks reuse the existing modules; all logging flows through the
//! tracing mirror into the shared event log, polled by the frontend.

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{self, Config};
use crate::events;
use crate::netsh::{self, InterfaceState, NetworkInfo};
use crate::pipeline::PipelineSummary;
use crate::wslattack::{self, AdapterMode, Ap, PixieOut};

pub struct AppState {
    pub cfg: Mutex<Config>,
    pub config_path: std::path::PathBuf,
    pub busy: Mutex<Option<String>>,
    pub task_started: AtomicBool,
    pub networks: Mutex<Option<Vec<NetworkInfo>>>,
    pub iface: Mutex<Option<InterfaceState>>,
    pub summary: Mutex<Option<PipelineSummary>>,
    pub stop: std::sync::atomic::AtomicBool,
    pub wsl_iface: Mutex<Option<String>>,
    pub wsl_adapter: Mutex<String>,
    pub wsl_aps: Mutex<Vec<Ap>>,
    pub pixie_out: Mutex<Vec<PixieOut>>,
}

impl AppState {
    fn new(cfg: Config) -> Self {
        let config_path =
            config::resolve_config_path(None).unwrap_or_else(|_| "config.toml".into());
        Self {
            cfg: Mutex::new(cfg),
            config_path,
            busy: Mutex::new(None),
            task_started: AtomicBool::new(false),
            networks: Mutex::new(None),
            iface: Mutex::new(None),
            summary: Mutex::new(None),
            stop: std::sync::atomic::AtomicBool::new(false),
            wsl_iface: Mutex::new(None),
            wsl_adapter: Mutex::new("未检测".into()),
            wsl_aps: Mutex::new(Vec::new()),
            pixie_out: Mutex::new(Vec::new()),
        }
    }

    fn spawn_task(
        st: &Arc<AppState>,
        name: &str,
        f: impl FnOnce(Arc<AppState>) + Send + 'static,
    ) -> bool {
        {
            let mut busy = st.busy.lock().unwrap();
            if busy.is_some() {
                return false; // one task at a time
            }
            *busy = Some(name.to_string());
        }
        let owned = st.clone();
        let logname = name.to_string();
        std::thread::spawn(move || {
            events::global().push(format!("--- {logname} 已启动 ---"));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(owned.clone())));
            if r.is_err() {
                events::global().push("任务异常退出（panic）");
            }
            events::global().push(format!("--- {logname} 结束 ---"));
            *owned.busy.lock().unwrap() = None;
        });
        true
    }
}

// ── routes ──────────────────────────────────────────────────────────────────

async fn index() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("web/index.html"))
}

async fn api_state(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let iface = st.iface.lock().unwrap().clone();
    let summary = st.summary.lock().unwrap().clone();
    let busy = st.busy.lock().unwrap().clone();
    let cfg = st.cfg.lock().unwrap().clone();
    Json(json!({
        "busy": busy,
        "iface": iface,
        "summary": summary,
        "config": cfg,
    }))
}

async fn api_networks(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let nets = st.networks.lock().unwrap().clone();
    Json(json!({ "networks": nets }))
}

async fn api_wsl(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({
        "adapter": st.wsl_adapter.lock().unwrap().clone(),
        "iface": st.wsl_iface.lock().unwrap().clone(),
        "aps": st.wsl_aps.lock().unwrap().clone(),
        "pixie": st.pixie_out.lock().unwrap().clone(),
    }))
}

#[derive(Deserialize)]
struct HideReq {
    bssids: Vec<String>,
}

async fn api_wsl_hide(State(st): State<Arc<AppState>>, Json(req): Json<HideReq>) -> Json<serde_json::Value> {
    let mut aps = st.wsl_aps.lock().unwrap();
    aps.retain(|a| !req.bssids.iter().any(|b| b.eq_ignore_ascii_case(&a.bssid)));
    Json(json!({ "ok": true, "remaining": aps.len() }))
}

#[derive(Deserialize)]
struct EventsQuery {
    since: Option<u64>,
}

async fn api_events(Query(q): Query<EventsQuery>) -> Json<serde_json::Value> {
    let since = q.since.unwrap_or(0);
    let (last, evs) = events::global().since(since);
    Json(json!({ "last": last, "events": evs }))
}

async fn api_config_post(
    State(st): State<Arc<AppState>>,
    Json(cfg): Json<Config>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    config::save(&cfg, &st.config_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败: {e:#}")))?;
    *st.cfg.lock().unwrap() = cfg;
    events::global().push("配置已保存到 config.toml");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct TaskReq {
    task: String,
    bssid: Option<String>,
    ch: Option<String>,
    essid: Option<String>,
}

async fn api_task(
    State(st): State<Arc<AppState>>,
    Json(req): Json<TaskReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let ok = match req.task.as_str() {
        "quick_scan" => AppState::spawn_task(&st, "快速扫描", |s| task_quick_scan(s)),
        "scan" => AppState::spawn_task(&st, "深度扫描", |s| task_scan(s)),
        "capture" => AppState::spawn_task(&st, "抓包", |s| task_capture(s)),
        "crack" => AppState::spawn_task(&st, "爆破", |s| task_crack(s)),
        "export" => AppState::spawn_task(&st, "导出密码", |s| task_export(s)),
        "full" => AppState::spawn_task(&st, "全流程", |s| task_full(s)),
        "dict_xato" => AppState::spawn_task(&st, "下载top100万", |s| task_dict(s, false)),
        "dict_rockyou" => AppState::spawn_task(&st, "下载rockyou", |s| task_dict(s, true)),
        "wsl_attach" => AppState::spawn_task(&st, "WSL接入网卡", |s| task_wsl_attach(s)),
        "wsl_scan" => AppState::spawn_task(&st, "WSL扫描", |s| task_wsl_scan(s)),
        "wsl_capture" => {
            let (b, c, e) = match (req.bssid.clone(), req.ch.clone(), req.essid.clone()) {
                (Some(b), Some(c), Some(e)) => (b, c, e),
                _ => return Err((StatusCode::BAD_REQUEST, "需要 bssid/ch/essid".into())),
            };
            AppState::spawn_task(&st, "WSL定向抓包", move |s| task_wsl_capture(s, b, c, e))
        }
        "wsl_batch_pin" => AppState::spawn_task(&st, "WSL批量PIN", |s| task_wsl_batch(s, true)),
        "wsl_batch_cap" => AppState::spawn_task(&st, "WSL批量抓包", |s| task_wsl_batch(s, false)),
        "stop_batch" => {
            st.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            events::global().push("已请求停止批量任务（当前项完成后生效）");
            return Ok(Json(json!({ "ok": true })));
        }
        "wsl_pixie" => {
            let (b, e) = match (req.bssid.clone(), req.essid.clone()) {
                (Some(b), Some(e)) => (b, e),
                _ => return Err((StatusCode::BAD_REQUEST, "需要 bssid/essid".into())),
            };
            AppState::spawn_task(&st, "WSL PixieDust", move |s| task_wsl_pixie(s, b, e))
        }
        other => {
            return Err((StatusCode::BAD_REQUEST, format!("unknown task: {}", other)));
        }
    };
    if ok {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err((StatusCode::CONFLICT, "已有任务在运行".into()))
    }
}

// ── task bodies ─────────────────────────────────────────────────────────────

fn task_quick_scan(st: Arc<AppState>) {
    let cfg = st.cfg.lock().unwrap().clone();
    match crate::scan::quick_scan(4, Duration::from_secs(3), None) {
        Ok(nets) => {
            let n = nets.len();
            let mut sorted = nets;
            sorted.sort_by_key(|x| std::cmp::Reverse(x.signal.unwrap_or(0)));
            *st.networks.lock().unwrap() = Some(sorted);
            events::global().push(format!("扫描完成，共 {} 个 SSID", n));
        }
        Err(e) => events::global().push(format!("扫描失败: {e:#}")),
    }
    let _ = cfg;
}

fn task_scan(st: Arc<AppState>) {
    let cfg = st.cfg.lock().unwrap().clone();
    let logs_dir = config::ensure_logs_dir();
    let restore_to = cfg.scan.disconnect_first.then(|| {
        netsh::show_interface().ok().and_then(|i| i.ssid).unwrap_or_default()
    });
    match crate::scan::scan(&cfg.scan, restore_to.as_deref()) {
        Ok(res) => {
            if let Err(e) = crate::scan::save_result(&res, &logs_dir) {
                events::global().push(format!("保存结果失败: {e:#}"));
            }
        }
        Err(e) => events::global().push(format!("扫描失败: {e:#}")),
    }
}

fn task_capture(st: Arc<AppState>) {
    let cfg = st.cfg.lock().unwrap().clone();
    let logs_dir = config::ensure_logs_dir();
    let caps_dir = crate::capture::caps_dir(&logs_dir);
    match crate::capture::capture(
        &cfg.capture,
        &cfg.crack.acng_bin,
        &cfg.targets.list,
        &caps_dir,
    ) {
        Ok(res) => {
            if let Err(e) = crate::capture::save_result(&res, &logs_dir) {
                events::global().push(format!("保存结果失败: {e:#}"));
            }
        }
        Err(e) => events::global().push(format!("抓包失败: {e:#}")),
    }
}

fn task_crack(st: Arc<AppState>) {
    let cfg = st.cfg.lock().unwrap().clone();
    let logs_dir = config::ensure_logs_dir();
    let caps_dir = crate::capture::caps_dir(&logs_dir);
    let dicts = cfg.effective_dicts();
    events::global().push(format!(
        "爆破：模式字典={}，字典文件 {} 个{}",
        if cfg.crack.use_patterns { "开" } else { "关" },
        dicts.len(),
        if cfg.crack.full8 { "（含全量8位数字）" } else { "" }
    ));
    match crate::crack::crack_caps(&cfg.crack.acng_bin, &caps_dir, &cfg.crack, &dicts, None) {
        Ok(res) => {
            if let Err(e) = crate::crack::save_result(&res, &logs_dir) {
                events::global().push(format!("保存结果失败: {e:#}"));
            }
        }
        Err(e) => events::global().push(format!("爆破失败: {e:#}")),
    }
}

fn task_export(_st: Arc<AppState>) {
    let logs_dir = config::ensure_logs_dir();
    match crate::pipeline::export_passwords(&logs_dir) {
        Ok(p) => events::global().push(format!("导出完成 -> {}", p.display())),
        Err(e) => events::global().push(format!("导出失败: {e:#}")),
    }
}

fn task_full(st: Arc<AppState>) {
    let cfg = st.cfg.lock().unwrap().clone();
    let logs_dir = config::ensure_logs_dir();
    match crate::pipeline::run_full(&cfg, &logs_dir, None) {
        Ok(s) => *st.summary.lock().unwrap() = Some(s),
        Err(e) => events::global().push(format!("全流程失败: {e:#}")),
    }
}

/// Match a target SSID to a scanned AP: exact -> contains -> token.
fn find_ap_for_target<'a>(target: &str, aps: &'a [Ap]) -> Option<&'a Ap> {
    let t = target.to_lowercase();
    if let Some(a) = aps.iter().find(|a| a.essid.to_lowercase() == t) {
        return Some(a);
    }
    if let Some(a) = aps.iter().find(|a| a.essid.to_lowercase().contains(&t)) {
        return Some(a);
    }
    let tokens: Vec<String> = regex::Regex::new(r"[-_]")
        .unwrap()
        .split(&t)
        .filter(|p| p.chars().count() >= 2)
        .map(|p| p.to_string())
        .collect();
    aps.iter()
        .find(|a| tokens.iter().any(|tok| a.essid.to_lowercase().contains(tok)))
}

fn task_wsl_batch(st: Arc<AppState>, do_pin: bool) {
    let (distro, tmo, sec) = {
        let c = st.cfg.lock().unwrap();
        (c.wsl.distro.clone(), c.wsl.pixie_timeout_sec, c.capture.duration_sec)
    };
    st.stop.store(false, std::sync::atomic::Ordering::Relaxed);
    let Some(iface) = st.wsl_iface.lock().unwrap().clone() else {
        events::global().push("先执行「接入网卡」");
        return;
    };
    let aps = st.wsl_aps.lock().unwrap().clone();
    let targets = st.cfg.lock().unwrap().targets.list.clone();
    if targets.is_empty() {
        events::global().push("目标列表为空 — 在扫描结果里点「加入」或手动输入");
        return;
    }
    let mode = if do_pin {
        format!("PixieDust（每目标超时 {tmo}s）")
    } else {
        format!("定向抓包（每目标 {sec}s）")
    };
    events::global().push(format!(
        "批量开始：{} 个目标 x {}",
        targets.len(),
        mode
    ));
    let logs_dir = config::ensure_logs_dir();
    let caps_abs = std::fs::canonicalize(logs_dir.join("caps"))
        .unwrap_or_else(|_| std::path::PathBuf::from("logs/caps"));
    let caps_win = caps_abs
        .to_string_lossy()
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .trim_start_matches("?")
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_string();
    let caps_str = if caps_win.as_bytes().get(1) == Some(&b':') {
        format!("/mnt/{}{}", (caps_win.as_bytes()[0] as char).to_lowercase(), &caps_win[2..])
    } else {
        caps_win.clone()
    };

    let mut done = 0usize;
    let mut hits = 0usize;
    let total = targets.len();
    for (idx, tgt) in targets.iter().enumerate() {
        if st.stop.load(std::sync::atomic::Ordering::Relaxed) {
            events::global().push(format!("批量中止于 {}/{}（用户停止）", idx, total));
            break;
        }
        let Some(ap) = find_ap_for_target(tgt, &aps) else {
            events::global().push(format!("  [{}/{}] {} — 扫描结果中不可见，跳过", idx + 1, total, tgt));
            continue;
        };
        let ap = ap.clone();
        events::global().push(format!(
            "  [{}/{}] {} ({}, ch{}) …",
            idx + 1, total, ap.essid, ap.bssid, ap.channel
        ));
        if do_pin {
            match wslattack::pixie(&distro, &iface, &ap.bssid, tmo) {
                Ok(p) => {
                    if p.pin.is_some() {
                        hits += 1;
                        events::global().push(format!(
                            "    *** 命中 {} PIN={} PSK={} ***",
                            ap.bssid,
                            p.pin.as_deref().unwrap_or("?"),
                            p.psk.as_deref().unwrap_or("(无)")
                        ));
                    } else {
                        events::global().push(format!("    未命中 {}", ap.bssid));
                    }
                    let mut all = st.pixie_out.lock().unwrap();
                    all.retain(|x| x.bssid != p.bssid);
                    all.push(p);
                }
                Err(e) => events::global().push(format!("    失败: {e:#}")),
            }
        } else {
            match wslattack::capture(&distro, &iface, &ap.bssid, &ap.channel, &ap.essid, sec, &caps_str) {
                Ok(file) => events::global().push(format!("    抓包完成 -> {file}")),
                Err(e) => events::global().push(format!("    抓包失败: {e:#}")),
            }
        }
        done += 1;
    }
    if do_pin {
        events::global().push(format!("批量结束：处理 {done} 个，命中 {hits} 个"));
    } else {
        events::global().push(format!("批量结束：抓包 {done} 个（logs/caps/），可点「爆破」跑字典"));
    }
}

fn task_dict(st: Arc<AppState>, rockyou: bool) {
    let dir = st.cfg.lock().unwrap().crack.dicts_dir.clone();
    let _ = std::fs::create_dir_all(&dir);
    let targets: Vec<(&str, &str, &str, u64)> = if rockyou {
        vec![(
            "rockyou.txt",
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
            "134MB",
            100_000_000,
        )]
    } else {
        vec![
            ("xato100w.txt", "https://fastly.jsdelivr.net/gh/danielmiessler/SecLists@master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt", "8.5MB", 1_000_000),
            ("xato100w.txt", "https://gcore.jsdelivr.net/gh/danielmiessler/SecLists@master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt", "8.5MB", 1_000_000),
            ("xato100w.txt", "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt", "8.5MB", 1_000_000),
        ]
    };
    for (name, url, size, min) in targets {
        let dest = dir.join(name);
        if dest.exists() {
            events::global().push(format!("已存在，跳过: {name}"));
            continue;
        }
        events::global().push(format!("下载 {name} ({size})…"));
        let s = std::process::Command::new("curl")
            .args(["-sfL", "--retry", "2", "--max-time", "1800", "-o"])
            .arg(&dest)
            .arg(url)
            .status();
        match s {
            Ok(s) if s.success() && dest.metadata().map(|m| m.len() >= min).unwrap_or(false) => {
                events::global().push(format!("下载完成: {name}"));
                break;
            }
            _ => {
                events::global().push("该源失败，尝试下一个镜像…");
                let _ = std::fs::remove_file(&dest);
            }
        }
    }
}

// ── WSL hardware tasks ──────────────────────────────────────────────────────

fn wsl_adapter_summary() -> String {
    match wslattack::adapter() {
        None => "未检测到（请插入网卡）".into(),
        Some(a) => {
            let mode = match a.mode {
                AdapterMode::Msc => "U盘模式(需切换)",
                AdapterMode::Wlan => "WiFi模式",
            };
            let state = if a.attached {
                "已接入WSL"
            } else if a.shared {
                "已共享"
            } else {
                "未共享"
            };
            format!("{} [{}|{}]", a.busid, mode, state)
        }
    }
}

fn task_wsl_attach(st: Arc<AppState>) {
    *st.wsl_adapter.lock().unwrap() = wsl_adapter_summary();
    let distro = st.cfg.lock().unwrap().wsl.distro.clone();

    // Fast path: already attached and an interface exists — nothing to do.
    if let Some(iface) = wslattack::find_iface(&distro) {
        let _ = wslattack::up_monitor(&distro, &iface);
        *st.wsl_iface.lock().unwrap() = Some(iface.clone());
        *st.wsl_adapter.lock().unwrap() = wsl_adapter_summary();
        events::global().push(format!("网卡已就绪（{iface} 监听模式），无需重新接入"));
        return;
    }

    let Some(mut info) = wslattack::adapter() else {
        events::global().push("未检测到 AIC 网卡 — 请插入 Tenda U2");
        return;
    };

    // MSC (fake CD) mode: switch it to WLAN.
    if info.mode == AdapterMode::Msc {
        if info.attached {
            // Already attached to WSL: eject from inside Kali (most reliable —
            // Windows cannot interfere with a device it doesn't own).
            events::global().push("U盘模式已挂在 WSL — 直接弹出切换…");
            match wslattack::eject_msc(&distro) {
                Ok(true) => events::global().push("弹出指令已发送，等待重新枚举…"),
                Ok(false) => events::global().push("WSL 内未找到 U 盘设备"),
                Err(e) => events::global().push(format!("弹出报错（通常仍会切换）: {e:#}")),
            }
        } else {
            // On Windows: try attaching first; if Windows claims the storage,
            // fall back to a Windows-side shell eject, then re-detect.
            events::global().push("U盘模式：尝试接入 WSL…");
            if let Err(e) = wslattack::attach(&info) {
                events::global().push(format!("接入被拒（{e:#}），改用 Windows 侧弹出…"));
                let _ = wslattack::windows_eject_msc();
            }
        }
        // Wait for re-enumeration into WLAN mode (up to ~15s).
        let mut wlan = None;
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if let Some(a) = wslattack::adapter() {
                if a.mode == AdapterMode::Wlan {
                    wlan = Some(a);
                    break;
                }
            }
        }
        let Some(wi) = wlan else {
            *st.wsl_adapter.lock().unwrap() = wsl_adapter_summary();
            events::global().push("未回到 WiFi 模式 — 拔插一次网卡后重试");
            return;
        };
        events::global().push("已切换为 WiFi 模式");
        info = wi;
    }

    // WLAN mode: attach to WSL (auto-elevate bind --force via UAC if needed).
    if info.attached {
        events::global().push("网卡已接入 WSL，跳过重复接入");
    } else {
        events::global().push(format!("接入 WSL: {}（未共享时会弹 UAC）", info.busid));
        if let Err(e) = wslattack::attach(&info) {
            events::global().push(format!("接入失败: {e:#}"));
            return;
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(2));
    // Stale-attach recovery: Windows may say "Attached" but the device is not
    // in the (restarted) WSL VM — detach and re-attach.
    if !wslattack::has_device(&distro) {
        events::global().push("WSL 内未看到设备 — 清除陈旧接入后重试…");
        wslattack::detach(&info.busid);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = std::process::Command::new(wslattack::USBIPD)
            .args(["attach", "--wsl", "--busid", &info.busid])
            .output();
        std::thread::sleep(std::time::Duration::from_secs(4));
    }
    // No udev coldplug in WSL — load the driver explicitly (self-healing).
    if let Err(e) = wslattack::load_driver(&distro) {
        events::global().push(format!("驱动加载失败: {e:#}"));
        return;
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    // WSL timing race: if the module loaded after the device, the USB probe
    // sometimes doesn't fire — reload the module once to force re-probe.
    let mut iface = wslattack::find_iface(&distro);
    if iface.is_none() {
        events::global().push("接口未出现，重载驱动强制重新探测…");
        let _ = wslattack::kali(&distro, "modprobe -r aic8800_fdrv aic_load_fw 2>/dev/null; sleep 1; modprobe aic8800_fdrv; sleep 3");
        iface = wslattack::find_iface(&distro);
    }
    let Some(iface) = iface else {
        events::global().push("WSL 内未发现 wlan 接口 — 检查 lsusb / 驱动");
        *st.wsl_adapter.lock().unwrap() = wsl_adapter_summary();
        return;
    };
    match wslattack::up_monitor(&distro, &iface) {
        Ok(()) => {
            *st.wsl_iface.lock().unwrap() = Some(iface.clone());
            *st.wsl_adapter.lock().unwrap() = wsl_adapter_summary();
            events::global().push(format!("网卡就绪：{iface} 已进监听模式"));
        }
        Err(e) => events::global().push(format!("监听模式失败: {e:#}")),
    }
}

fn task_wsl_scan(st: Arc<AppState>) {
    let distro = st.cfg.lock().unwrap().wsl.distro.clone();
    let Some(iface) = st.wsl_iface.lock().unwrap().clone() else {
        events::global().push("先执行「接入网卡」");
        return;
    };
    match wslattack::scan_aps(&distro, &iface) {
        Ok(aps) => {
            let n = aps.len();
            events::global().push(format!("WSL 扫描完成：{} 个 AP（按信号排序）", n));
            for a in aps.iter().take(15) {
                events::global().push(format!(
                    "  {:18} {} dBm ch{} {}",
                    if a.essid.len() > 18 { &a.essid[..18] } else { &a.essid },
                    a.power,
                    a.channel,
                    a.bssid
                ));
            }
            *st.wsl_aps.lock().unwrap() = aps;
        }
        Err(e) => events::global().push(format!("WSL 扫描失败: {e:#}")),
    }
}

fn task_wsl_capture(st: Arc<AppState>, bssid: String, ch: String, essid: String) {
    let distro = st.cfg.lock().unwrap().wsl.distro.clone();
    let sec = st.cfg.lock().unwrap().capture.duration_sec;
    let Some(iface) = st.wsl_iface.lock().unwrap().clone() else {
        events::global().push("先执行「接入网卡」");
        return;
    };
    let logs_dir = config::ensure_logs_dir();
    let caps_abs = std::fs::canonicalize(logs_dir.join("caps")).unwrap_or_else(|_| std::path::PathBuf::from("logs/caps"));
    // strip the \\?\ canonical prefix and map X:\... -> /mnt/x/... for Linux
    let caps_win = caps_abs
        .to_string_lossy()
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .trim_start_matches("?")
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_string();
    let caps_str = if caps_win.as_bytes().get(1) == Some(&b':') {
        format!("/mnt/{}{}", (caps_win.as_bytes()[0] as char).to_lowercase(), &caps_win[2..])
    } else {
        caps_win.clone()
    };
    events::global().push(format!("定向抓包 {essid} ({bssid} ch{ch}) {sec}s — 等待目标客户端产生握手…"));
    match wslattack::capture(&distro, &iface, &bssid, &ch, &essid, sec, &caps_str) {
        Ok(file) => events::global().push(format!("抓包完成 -> {file}（可用「爆破」跑字典）")),
        Err(e) => events::global().push(format!("抓包失败: {e:#}")),
    }
}

fn task_wsl_pixie(st: Arc<AppState>, bssid: String, essid: String) {
    let (distro, tmo) = {
        let c = st.cfg.lock().unwrap();
        (c.wsl.distro.clone(), c.wsl.pixie_timeout_sec)
    };
    let Some(iface) = st.wsl_iface.lock().unwrap().clone() else {
        events::global().push("先执行「接入网卡」");
        return;
    };
    events::global().push(format!("PixieDust 攻击 {essid} ({bssid})，超时 {tmo}s…"));
    match wslattack::pixie(&distro, &iface, &bssid, tmo) {
        Ok(p) => {
            let hit = p.pin.is_some();
            events::global().push(if hit {
                format!(
                    "*** PixieDust 命中 {} PIN={} PSK={} ***",
                    bssid,
                    p.pin.as_deref().unwrap_or("?"),
                    p.psk.as_deref().unwrap_or("(无)")
                )
            } else {
                format!("PixieDust 未命中 {bssid}（固件不易感或目标无 WPS）")
            });
            let mut all = st.pixie_out.lock().unwrap();
            all.retain(|x| x.bssid != p.bssid);
            all.push(p);
        }
        Err(e) => events::global().push(format!("PixieDust 失败: {e:#}")),
    }
}

// ── server + window ─────────────────────────────────────────────────────────

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/networks", get(api_networks))
        .route("/api/wsl", get(api_wsl))
        .route("/api/wsl/hide", post(api_wsl_hide))
        .route("/api/events", get(api_events))
        .route("/api/config", post(api_config_post))
        .route("/api/task", post(api_task))
        .with_state(state)
}

fn start_server(state: Arc<AppState>) -> Result<SocketAddr> {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    let router = build_router(state);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind 127.0.0.1");
            let _ = tx.send(listener.local_addr().unwrap());
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("server error: {e}");
            }
        });
    });
    rx.recv().context("server did not start")
}

/// GUI entry point: web UI in a WebView2 window. If WebView2 is unavailable,
/// print the URL and keep the server running so any browser works.
pub fn start(cfg: Config) -> Result<()> {
    let state = Arc::new(AppState::new(cfg));
    let logs_dir = config::ensure_logs_dir();
    let _ = std::fs::create_dir_all(&logs_dir);

    // periodic connection-status + adapter refresh
    {
        let st = state.clone();
        std::thread::spawn(move || loop {
            if st.busy.lock().unwrap().is_none() {
                if let Ok(i) = netsh::show_interface() {
                    *st.iface.lock().unwrap() = Some(i);
                }
                *st.wsl_adapter.lock().unwrap() = wsl_adapter_summary();
            }
            std::thread::sleep(Duration::from_secs(10));
        });
    }

    let addr = start_server(state.clone())?;
    let url = format!("http://{addr}/");
    events::global().push(format!("Web UI: {url}"));
    println!("web UI: {url}");

    // webview window (must be on the main thread)
    let event_loop = tao::event_loop::EventLoop::new();
    let window = tao::window::WindowBuilder::new()
        .with_title("WiFi Toolkit")
        .with_inner_size(tao::dpi::LogicalSize::new(1220.0, 820.0))
        .build(&event_loop)
        .context("create window")?;

    let webview = wry::WebViewBuilder::new()
        .with_url(&url)
        .build(&window);
    if let Err(e) = webview {
        tracing::warn!("webview unavailable ({e}); serving {url} until Ctrl+C");
        println!("WebView2 不可用，用浏览器打开 {url} 即可使用");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    event_loop.run(move |event, _, control| {
        if let tao::event::Event::WindowEvent {
            event: tao::event::WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control = tao::event_loop::ControlFlow::Exit;
        }
    });
    std::process::exit(0);
}
