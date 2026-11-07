//! egui GUI: left config panel (SSID targets, pins, paths, scan-to-pick),
//! right execution panel with live log + status.

use anyhow::Result;
use eframe::egui;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{self, Config};
use crate::netsh::{self, InterfaceState, NetworkInfo};
use crate::pipeline::{self, PipelineSummary};

const MAX_LOG_LINES: usize = 3000;

type Shared<T> = Arc<Mutex<Option<T>>>;

pub struct App {
    cfg: Config,
    config_path: std::path::PathBuf,
    tx: mpsc::Sender<String>,
    rx: mpsc::Receiver<String>,
    busy: Arc<Mutex<Option<String>>>,
    logs: Vec<String>,
    networks: Shared<Vec<NetworkInfo>>,
    iface: Shared<InterfaceState>,
    summary: Shared<PipelineSummary>,
    // String mirrors of PathBuf config fields for TextEdit
    acng_bin_str: String,
    dict_str: String,
    new_target: String,
    new_pin: String,
    last_status_refresh: Instant,
    saved_toast: f32,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, cfg: Config) -> Self {
        load_cjk_fonts(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel();
        let config_path =
            config::resolve_config_path(None).unwrap_or_else(|_| "config.toml".into());
        let acng_bin_str = cfg.crack.acng_bin.to_string_lossy().into_owned();
        let dict_str = cfg.crack.dict.to_string_lossy().into_owned();
        let app = Self {
            cfg,
            config_path,
            tx: tx.clone(),
            rx,
            busy: Arc::new(Mutex::new(None)),
            logs: Vec::new(),
            networks: Arc::new(Mutex::new(None)),
            iface: Arc::new(Mutex::new(None)),
            summary: Arc::new(Mutex::new(None)),
            acng_bin_str,
            dict_str,
            new_target: String::new(),
            new_pin: String::new(),
            last_status_refresh: Instant::now() - Duration::from_secs(60),
            saved_toast: 0.0,
        };
        spawn_status_refresh(app.iface.clone(), app.busy.clone(), app.tx.clone());
        app
    }

    fn commit_str_fields(&mut self) {
        if !self.acng_bin_str.trim().is_empty() {
            self.cfg.crack.acng_bin = self.acng_bin_str.trim().into();
        }
        if !self.dict_str.trim().is_empty() {
            self.cfg.crack.dict = self.dict_str.trim().into();
        }
    }

    fn spawn<F>(&mut self, name: &str, f: F)
    where
        F: FnOnce(mpsc::Sender<String>) + Send + 'static,
    {
        let mut guard = self.busy.lock().unwrap();
        if guard.is_some() {
            return; // one task at a time
        }
        *guard = Some(name.to_string());
        drop(guard);

        let tx = self.tx.clone();
        let busy = self.busy.clone();
        self.logs.push(format!("--- {} 已启动 ---", name));
        std::thread::spawn(move || {
            f(tx);
            *busy.lock().unwrap() = None;
        });
    }

    fn poll_channel(&mut self) {
        while let Ok(line) = self.rx.try_recv() {
            self.logs.push(line);
            if self.logs.len() > MAX_LOG_LINES {
                let excess = self.logs.len() - MAX_LOG_LINES;
                self.logs.drain(0..excess);
            }
        }
        if self.last_status_refresh.elapsed() > Duration::from_secs(15) {
            self.last_status_refresh = Instant::now();
            spawn_status_refresh(self.iface.clone(), self.busy.clone(), self.tx.clone());
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_channel();
        let busy_flag = self.busy.lock().unwrap().is_some();

        egui::SidePanel::left("config_panel")
            .exact_width(350.0)
            .show(ctx, |ui| self.config_panel(ui, busy_flag));

        egui::CentralPanel::default().show(ctx, |ui| self.run_panel(ui, busy_flag));

        if self.saved_toast > 0.0 {
            self.saved_toast = (self.saved_toast - ctx.input(|i| i.unstable_dt)).max(0.0);
        }

        ctx.request_repaint_after(Duration::from_millis(300));
    }
}

impl App {
    fn config_panel(&mut self, ui: &mut egui::Ui, busy: bool) {
        ui.heading("目标 SSID 列表");
        ui.separator();

        let mut remove_idx: Option<usize> = None;
        egui::ScrollArea::vertical().max_height(130.0).show(ui, |ui| {
            for (i, t) in self.cfg.targets.list.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(t)
                            .desired_width(ui.available_width() - 34.0),
                    );
                    if ui.add_enabled(!busy, egui::Button::new("删除").small()).clicked() {
                        remove_idx = Some(i);
                    }
                });
            }
        });
        if let Some(i) = remove_idx {
            self.cfg.targets.list.remove(i);
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_target)
                    .hint_text("手动输入 SSID…")
                    .desired_width(ui.available_width() - 70.0),
            );
            let add = ui.add_enabled(
                !self.new_target.trim().is_empty(),
                egui::Button::new("+ 添加"),
            );
            if add.clicked() {
                let t = self.new_target.trim().to_string();
                if !self.cfg.targets.list.contains(&t) {
                    self.cfg.targets.list.push(t);
                }
                self.new_target.clear();
            }
        });

        ui.separator();
        ui.heading("扫描附近网络");
        ui.horizontal(|ui| {
            let btn = ui.add_enabled(!busy, egui::Button::new("扫描网卡（不断网）"));
            if btn.clicked() {
                let networks_slot = self.networks.clone();
                self.spawn("quick-scan", move |tx| {
                    let _ = tx.send("主动扫描 4 轮（每轮触发 WlanScan 全信道扫描，不断网）…".into());
                    match crate::scan::quick_scan(4, Duration::from_secs(3), Some(&tx)) {
                        Ok(nets) => {
                            let _ = tx.send(format!("扫描完成，共 {} 个 SSID，在左侧勾选加入目标", nets.len()));
                            *networks_slot.lock().unwrap() = Some(nets);
                        }
                        Err(e) => {
                            let _ = tx.send(format!("扫描失败: {:#}", e));
                        }
                    }
                });
            }
            if busy {
                ui.label("任务运行中…");
            }
        });

        let mut nets_opt = self.networks.lock().unwrap().clone();
        if let Some(nets) = nets_opt.as_mut() {
            // Strongest first; unknown signal last
            nets.sort_by_key(|n| std::cmp::Reverse(n.signal.unwrap_or(0)));
        }
        if let Some(nets) = nets_opt {
            egui::ScrollArea::vertical().max_height(210.0).show(ui, |ui| {
                egui::Grid::new("net_table").striped(true).min_col_width(60.0).show(ui, |ui| {
                    ui.strong("SSID");
                    ui.strong("频道");
                    ui.strong("信号");
                    ui.strong("加密");
                    ui.strong("");
                    ui.end_row();
                    for n in &nets {
                        let display = if n.ssid == "(empty)" { "（隐藏网络）" } else { &n.ssid };
                        ui.label(display);
                        ui.label(match &n.channel {
                            Some(c) => format!("{}", c),
                            None => "未知".to_string(),
                        });
                        match n.signal {
                            Some(sig) => {
                                let color = if sig >= 70 {
                                    egui::Color32::from_rgb(80, 200, 80)
                                } else if sig >= 40 {
                                    egui::Color32::from_rgb(230, 180, 60)
                                } else {
                                    egui::Color32::from_rgb(230, 90, 70)
                                };
                                let bars = if sig >= 70 {
                                    "■■■■"
                                } else if sig >= 40 {
                                    "■■□□"
                                } else {
                                    "■□□□"
                                };
                                ui.label(
                                    egui::RichText::new(format!("{} {}%", bars, sig)).color(color),
                                );
                            }
                            None => {
                                ui.label(
                                    egui::RichText::new("未知").color(egui::Color32::GRAY),
                                );
                            }
                        }
                        ui.label(n.auth.as_deref().unwrap_or("加密未知"));
                        let already = self.cfg.targets.list.contains(&n.ssid);
                        if already {
                            ui.label("已加");
                        } else if ui.add_enabled(!busy, egui::Button::new("+加入").small()).clicked() {
                            self.cfg.targets.list.push(n.ssid.clone());
                        }
                        ui.end_row();
                    }
                });
            });
        }

        ui.separator();
        ui.collapsing("高级设置（PIN / 时长 / 路径）", |ui| {
            ui.add_space(4.0);
            ui.label("WPS PIN 列表");
            let mut rm_pin: Option<usize> = None;
            for (i, p) in self.cfg.wps.pins.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(p).desired_width(120.0));
                    if ui.small_button("删除").clicked() {
                        rm_pin = Some(i);
                    }
                });
            }
            if let Some(i) = rm_pin {
                self.cfg.wps.pins.remove(i);
            }
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_pin)
                        .hint_text("8位PIN")
                        .desired_width(120.0),
                );
                if ui.small_button("+").clicked() && self.new_pin.trim().len() == 8 {
                    let p = self.new_pin.trim().to_string();
                    if !self.cfg.wps.pins.contains(&p) {
                        self.cfg.wps.pins.push(p);
                    }
                    self.new_pin.clear();
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("扫描时长");
                ui.add(egui::DragValue::new(&mut self.cfg.scan.duration_sec).suffix("s"));
                ui.label("抓包时长");
                ui.add(egui::DragValue::new(&mut self.cfg.capture.duration_sec).suffix("s"));
            });
            ui.checkbox(
                &mut self.cfg.scan.disconnect_first,
                "扫描前短暂断网（能看到更多AP）",
            );
            ui.add_space(6.0);
            ui.label("aircrack 目录");
            ui.add(egui::TextEdit::singleline(&mut self.acng_bin_str).desired_width(ui.available_width()));
            ui.label("字典路径（rockyou 缺失时自动用 mini_dict）");
            ui.add(egui::TextEdit::singleline(&mut self.dict_str).desired_width(ui.available_width()));
        });

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("保存配置").clicked() {
                self.commit_str_fields();
                match config::save(&self.cfg, &self.config_path) {
                    Ok(()) => {
                        self.saved_toast = 2.0;
                        self.logs.push("配置已保存到 config.toml".into());
                    }
                    Err(e) => self.logs.push(format!("保存失败: {:#}", e)),
                }
            }
            if self.saved_toast > 0.0 {
                ui.colored_label(egui::Color32::GREEN, "已保存");
            }
        });
    }

    fn run_panel(&mut self, ui: &mut egui::Ui, busy: bool) {
        let iface = self.iface.lock().unwrap().clone();
        match &iface {
            Some(i) => {
                ui.horizontal(|ui| {
                    ui.label("当前连接:");
                    ui.strong(i.ssid.as_deref().unwrap_or("(未连接)"));
                    ui.label(i.state.as_deref().unwrap_or(""));
                    if ui.small_button("刷新").clicked() {
                        self.last_status_refresh = Instant::now();
                        spawn_status_refresh(self.iface.clone(), self.busy.clone(), self.tx.clone());
                    }
                });
            }
            None => {
                ui.label("当前连接: (读取中…)");
            }
        }
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            let mk = |ui: &mut egui::Ui, label: &str| {
                ui.add_enabled(!busy, egui::Button::new(label))
            };
            if mk(ui, "扫描").clicked() {
                self.launch_scan();
            }
            if mk(ui, "WPS 探测").clicked() {
                self.launch_wps();
            }
            if mk(ui, "抓包").clicked() {
                self.launch_capture();
            }
            if mk(ui, "爆破").clicked() {
                self.launch_crack();
            }
            if mk(ui, "导出密码").clicked() {
                self.launch_export();
            }
            let run_btn = ui.add_enabled(
                !busy,
                egui::Button::new("运行全流程").fill(egui::Color32::from_rgb(30, 90, 40)),
            );
            if run_btn.clicked() {
                self.launch_full();
            }
        });

        let summary = self.summary.lock().unwrap().clone();
        if let Some(s) = &summary {
            ui.separator();
            ui.label(format!(
                "上次全流程: {}s · 网络恢复: {} · 原 {} → 现 {}",
                s.elapsed_sec,
                if s.restored { "是" } else { "否" },
                s.original_ssid,
                s.final_ssid.as_deref().unwrap_or("(未连接)")
            ));
            if !s.wps_cracked.is_empty() {
                ui.colored_label(egui::Color32::YELLOW, format!("WPS 破解: {:?}", s.wps_cracked));
            }
            if !s.crack_found.is_empty() {
                ui.colored_label(
                    egui::Color32::LIGHT_GREEN,
                    format!("字典破解: {:?}", s.crack_found),
                );
            }
        }

        ui.separator();
        ui.label("执行日志");
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for line in &self.logs {
                    ui.label(egui::RichText::new(line).monospace().size(11.0));
                }
            });
    }

    fn launch_scan(&mut self) {
        let cfg = self.cfg.clone();
        let logs_dir = config::ensure_logs_dir();
        self.spawn("scan", move |tx| {
            let restore_to = cfg.scan.disconnect_first.then(|| {
                netsh::show_interface().ok().and_then(|i| i.ssid).unwrap_or_default()
            });
            let _ = tx.send(format!(
                "扫描 {}s（disconnect_first={}）…",
                cfg.scan.duration_sec, cfg.scan.disconnect_first
            ));
            match crate::scan::scan(&cfg.scan, restore_to.as_deref()) {
                Ok(res) => {
                    let _ = tx.send(format!("扫描完成: {} 个 SSID / {} 轮", res.total_ssids, res.rounds));
                    if let Err(e) = crate::scan::save_result(&res, &logs_dir) {
                        let _ = tx.send(format!("保存结果失败: {:#}", e));
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("扫描失败: {:#}", e));
                }
            }
        });
    }

    fn launch_wps(&mut self) {
        let cfg = self.cfg.clone();
        let logs_dir = config::ensure_logs_dir();
        self.spawn("wps", move |tx| {
            let _ = tx.send(format!("WPS 探测目标: {:?}", cfg.targets.list));
            match crate::wps::probe(&cfg.wps, &cfg.targets.list) {
                Ok(res) => {
                    for (t, r) in &res.targets {
                        let _ = tx.send(format!(
                            "  {}: {}",
                            t,
                            if r.cracked == Some(true) {
                                "破解成功"
                            } else if r.found == Some(false) {
                                "不可见"
                            } else {
                                "未成功"
                            }
                        ));
                    }
                    if let Err(e) = crate::wps::save_result(&res, &logs_dir) {
                        let _ = tx.send(format!("保存结果失败: {:#}", e));
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("WPS 探测失败: {:#}", e));
                }
            }
        });
    }

    fn launch_capture(&mut self) {
        let cfg = self.cfg.clone();
        let logs_dir = config::ensure_logs_dir();
        self.spawn("capture", move |tx| {
            let caps_dir = crate::capture::caps_dir(&logs_dir);
            match crate::capture::capture(
                &cfg.capture,
                &cfg.crack.acng_bin,
                &cfg.targets.list,
                &caps_dir,
            ) {
                Ok(res) => {
                    for r in &res {
                        let _ = tx.send(format!(
                            "  {}: {}",
                            r.target,
                            if r.supported { "完成" } else { "网卡不支持（仅 AirPcap 硬件）" }
                        ));
                    }
                    if let Err(e) = crate::capture::save_result(&res, &logs_dir) {
                        let _ = tx.send(format!("保存结果失败: {:#}", e));
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("抓包失败: {:#}", e));
                }
            }
        });
    }

    fn launch_crack(&mut self) {
        let cfg = self.cfg.clone();
        let logs_dir = config::ensure_logs_dir();
        self.spawn("crack", move |tx| {
            match cfg.effective_dict() {
                Some(dict) => {
                    let caps_dir = crate::capture::caps_dir(&logs_dir);
                    match crate::crack::crack_caps(
                        &cfg.crack.acng_bin,
                        &caps_dir,
                        &dict,
                        cfg.crack.timeout_sec,
                    ) {
                        Ok(res) => {
                            for r in &res {
                                let _ = tx.send(format!(
                                    "  {}: {}",
                                    r.cap,
                                    if r.cracked {
                                        format!("破解成功 = {}", r.password.as_deref().unwrap_or("(未知)"))
                                    } else {
                                        "未破解".into()
                                    }
                                ));
                            }
                            if let Err(e) = crate::crack::save_result(&res, &logs_dir) {
                                let _ = tx.send(format!("保存结果失败: {:#}", e));
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(format!("爆破失败: {:#}", e));
                        }
                    }
                }
                None => {
                    let _ = tx.send("找不到字典文件（rockyou / mini_dict 均缺失）".into());
                }
            }
        });
    }

    fn launch_export(&mut self) {
        let logs_dir = config::ensure_logs_dir();
        self.spawn("export", move |tx| match pipeline::export_passwords(&logs_dir) {
            Ok(p) => {
                let _ = tx.send(format!("导出完成 -> {}", p.display()));
            }
            Err(e) => {
                let _ = tx.send(format!("导出失败: {:#}", e));
            }
        });
    }

    fn launch_full(&mut self) {
        let cfg = self.cfg.clone();
        let logs_dir = config::ensure_logs_dir();
        let summary_slot = self.summary.clone();
        self.spawn("full-pipeline", move |tx| {
            match pipeline::run_full(&cfg, &logs_dir, Some(&tx)) {
                Ok(s) => {
                    *summary_slot.lock().unwrap() = Some(s);
                }
                Err(e) => {
                    let _ = tx.send(format!("全流程失败: {:#}", e));
                }
            }
        });
    }
}

fn spawn_status_refresh(
    slot: Shared<InterfaceState>,
    busy: Arc<Mutex<Option<String>>>,
    tx: mpsc::Sender<String>,
) {
    if busy.lock().unwrap().is_some() {
        return;
    }
    std::thread::spawn(move || match netsh::show_interface() {
        Ok(i) => {
            *slot.lock().unwrap() = Some(i);
        }
        Err(e) => {
            let _ = tx.send(format!("读取网卡状态失败: {:#}", e));
        }
    });
}

/// Load a CJK-capable font so Chinese renders (egui default fonts lack CJK glyphs).
fn load_cjk_fonts(ctx: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc", // Microsoft YaHei
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\Deng.ttf",
    ];
    for path in candidates {
        if let Ok(data) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data
                .insert("cjk".to_owned(), Arc::new(egui::FontData::from_owned(data)));
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                if let Some(list) = fonts.families.get_mut(&family) {
                    list.insert(0, "cjk".to_owned());
                }
            }
            ctx.set_fonts(fonts);
            tracing::info!("loaded CJK font from {}", path);
            return;
        }
    }
    tracing::warn!("no CJK font found; Chinese text may render as boxes");
}

/// GUI entry point.
pub fn start(cfg: Config) -> Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1150.0, 720.0])
            .with_title("WiFi Toolkit"),
        ..Default::default()
    };
    eframe::run_native(
        "wifi-toolkit",
        opts,
        Box::new(move |cc| Ok(Box::new(App::new(cc, cfg)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;
    Ok(())
}
