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

pub struct AppState {
    pub cfg: Mutex<Config>,
    pub config_path: PathBuf,
    pub busy: Mutex<Option<String>>,
    pub task_started: AtomicBool,
    pub networks: Mutex<Option<Vec<NetworkInfo>>>,
    pub iface: Mutex<Option<InterfaceState>>,
    pub summary: Mutex<Option<PipelineSummary>>,
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
}

async fn api_task(
    State(st): State<Arc<AppState>>,
    Json(req): Json<TaskReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let ok = match req.task.as_str() {
        "quick_scan" => AppState::spawn_task(&st, "快速扫描", |s| task_quick_scan(s)),
        "scan" => AppState::spawn_task(&st, "深度扫描", |s| task_scan(s)),
        "wps" => AppState::spawn_task(&st, "WPS 探测", |s| task_wps(s)),
        "capture" => AppState::spawn_task(&st, "抓包", |s| task_capture(s)),
        "crack" => AppState::spawn_task(&st, "爆破", |s| task_crack(s)),
        "export" => AppState::spawn_task(&st, "导出密码", |s| task_export(s)),
        "full" => AppState::spawn_task(&st, "全流程", |s| task_full(s)),
        "dict_xato" => AppState::spawn_task(&st, "下载top100万", |s| task_dict(s, false)),
        "dict_rockyou" => AppState::spawn_task(&st, "下载rockyou", |s| task_dict(s, true)),
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

fn task_wps(st: Arc<AppState>) {
    let cfg = st.cfg.lock().unwrap().clone();
    let logs_dir = config::ensure_logs_dir();
    match crate::wps::probe(&cfg.wps, &cfg.targets.list) {
        Ok(res) => {
            if let Err(e) = crate::wps::save_result(&res, &logs_dir) {
                events::global().push(format!("保存结果失败: {e:#}"));
            }
        }
        Err(e) => events::global().push(format!("WPS 探测失败: {e:#}")),
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

// ── server + window ─────────────────────────────────────────────────────────

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/networks", get(api_networks))
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

    // periodic connection-status refresh
    {
        let st = state.clone();
        std::thread::spawn(move || loop {
            if st.busy.lock().unwrap().is_none() {
                if let Ok(i) = netsh::show_interface() {
                    *st.iface.lock().unwrap() = Some(i);
                }
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
