# wifi-toolkit

纯 Rust 实现的 WiFi 工具箱：扫描 → WPS PIN 探测 → airodump 抓包 → aircrack-ng 离线爆破 → 自动恢复网络。
GUI（WebView2 webview）+ CLI 双模式，完整日志。

> 仅供授权的安全测试 / 自有网络管理使用。

## 构建

```bat
cargo build --release
```

产物：`target\release\wifi-toolkit.exe`

## 使用

### GUI（webview）
```bat
wifi-toolkit.exe           :: 或 wifi-toolkit.exe gui
```
- WebView2 窗口加载 axum 本地页面（127.0.0.1 随机端口），无 GPU 兼容性问题
- 左栏：目标 SSID 列表（文本编辑 + 「扫描网卡」4 轮主动扫描后一键加入）、PIN 列表、时长、字典管理
- 右栏：执行按钮（深度扫描 / WPS / 抓包 / 爆破 / 导出密码 / ▶全流程）+ 实时日志 + 上次全流程结果
- 若 WebView2 不可用，程序会打印 URL 并保持服务运行——用任意浏览器打开同一地址即可
- 全部 tracing 日志通过 mirror 层实时进入页面日志区

### CLI
```bat
wifi-toolkit.exe run                :: 全流程（无人值守，结束自动恢复原网络）
wifi-toolkit.exe scan               :: 多轮扫描（读 config.toml）
wifi-toolkit.exe nets               :: 快速扫描（触发主动扫描，不断网）
wifi-toolkit.exe wps                :: WPS PIN 探测
wifi-toolkit.exe capture            :: airodump-ng 抓包
wifi-toolkit.exe crack              :: 爆破 logs\caps\ 下全部 .cap
wifi-toolkit.exe crack <cap> <dict> :: 指定 cap 和字典；dict 为 - 时用内置模式字典
wifi-toolkit.exe dict               :: 列出字典（行数/大小）
wifi-toolkit.exe dict update        :: 下载 top100万 + rockyou 字典
wifi-toolkit.exe reconnect <SSID>   :: 手动重连
wifi-toolkit.exe export-passwords   :: 导出已保存 profile 密码表
```

## 离线爆破

词源按序尝试，命中即停：
1. **内置模式字典**（stdin 流式喂给 aircrack，不占磁盘，约 5 万条）：
   常用数字/重复序列 → 1900-2026 全部有效日期 → 拼音×数字后缀组合
   （`full8 = true` 时追加全量 8 位数字 1 亿条，约 10 分钟+/目标）
2. **字典文件**：`dict`（rockyou，1434 万条）→ `dicts_dir` 下全部 .txt/.dic/.lst → 兜底 mini_dict

stdin 模式会先用 `aircrack-ng <cap>` 自动探测目标 BSSID（`-w -` 要求显式选网）。
进度事件实时显示（每 10%），支持硬超时杀进程。

验证：`dicts/test/wpa.cap` 是 aircrack-ng 官方测试包（密码 `biscotte`），
`cargo test` 里的两个端到端测试用它回归文件字典和 stdin 两条链路。

## 配置（config.toml）

- `[targets] list` — WPS / 抓包共用的 SSID 目标列表（支持部分匹配：`tp3-204` 可匹配 `3--204`）
- `[wps] pins` — PIN 候选列表
- `[scan] disconnect_first` — 扫描前短暂断网（能看到更多 AP）
- `[crack] dict / dicts_dir / use_patterns / full8` — 字典与爆破模式（见「离线爆破」）
- `[restore] ssid` — 留空 = 运行前自动记住当前网络

## 日志

- `logs\wifi-toolkit.log` — tracing 按天滚动
- `logs\scan_results.json` / `wps_results.json` / `crack_results.json` / `summary.json` — 各步骤结构化结果
- `logs\passwords_export.txt` — 导出的已保存密码表
- `logs\caps\` — airodump 抓包输出

## 自动恢复机制

`restore.rs::RestoreGuard`：流程开始记住当前 SSID，guard Drop（含 panic）时重连，等效 Python 版 try/finally。

## 已知限制

- airodump-ng Windows 版仅支持 AirPcap USB 硬件；内置 Intel AX201 会报 `not supported`（抓包步骤会记录失败但流程继续）
- netsh 输出按中文 Windows（GBK）解析；英文系统需自行调整字段正则
