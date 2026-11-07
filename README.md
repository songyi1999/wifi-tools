# wifi-toolkit

纯 Rust 实现的 WiFi 工具箱：扫描 → WPS PIN 探测 → airodump 抓包 → aircrack-ng 离线爆破 → 自动恢复网络。
GUI（egui）+ CLI 双模式，完整日志。

> 仅供授权的安全测试 / 自有网络管理使用。

## 构建

```bat
cargo build --release
```

产物：`target\release\wifi-toolkit.exe`

## 使用

### GUI（默认）
```bat
wifi-toolkit.exe           :: 或 wifi-toolkit.exe gui
```
- 左栏：SSID 目标列表（手输 + 「扫描网卡」列出附近 AP 后一键加入）、PIN 列表、时长、路径
- 右栏：执行按钮（扫描 / WPS / 抓包 / 爆破 / ▶ 全流程）+ 实时日志 + 连接状态

### CLI
```bat
wifi-toolkit.exe run                :: 全流程（无人值守，结束自动恢复原网络）
wifi-toolkit.exe scan               :: 多轮扫描（读 config.toml）
wifi-toolkit.exe wps                :: WPS PIN 探测
wifi-toolkit.exe capture            :: airodump-ng 抓包
wifi-toolkit.exe crack              :: aircrack-ng 离线爆破
wifi-toolkit.exe reconnect <SSID>   :: 手动重连
wifi-toolkit.exe export-passwords   :: 导出已保存 profile 密码表
```

## 配置（config.toml）

- `[targets] list` — WPS / 抓包共用的 SSID 目标列表（支持部分匹配：`tp3-204` 可匹配 `3--204`）
- `[wps] pins` — PIN 候选列表
- `[scan] disconnect_first` — 扫描前短暂断网（能看到更多 AP）
- `[crack] acng_bin / dict` — aircrack-ng 路径与字典
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
