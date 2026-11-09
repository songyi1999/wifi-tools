//! netsh wlan wrappers with GBK decoding (Chinese Windows locale).

use anyhow::{Context, Result};
use encoding_rs::GBK;
use regex::Regex;
use serde::Serialize;
use std::process::Command;

/// Decode command output: netsh on Chinese Windows emits GBK (cp936).
pub fn decode_gbk(bytes: &[u8]) -> String {
    let (decoded, _, had_errors) = GBK.decode(bytes);
    let s = decoded.into_owned();
    if had_errors {
        // Fallback: lossy UTF-8 in case the system speaks UTF-8
        let alt = String::from_utf8_lossy(bytes);
        if alt.contains('\u{FFFD}') && !s.contains('\u{FFFD}') {
            return s;
        }
        return alt.into_owned();
    }
    s
}

pub struct NetshOutput {
    pub stdout: String,
    pub returncode: i32,
}

impl NetshOutput {
    pub fn ok(&self) -> bool {
        self.returncode == 0
    }
}

/// Run `netsh <args>` capturing GBK stdout, timeout via external guard is not
/// available in std; netsh wlan commands are fast, so we rely on them being quick.
pub fn run_netsh(args: &[&str]) -> Result<NetshOutput> {
    let out = Command::new("netsh")
        .args(args)
        .output()
        .context("spawning netsh (is it on PATH?)")?;
    Ok(NetshOutput {
        stdout: decode_gbk(&out.stdout),
        returncode: out.status.code().unwrap_or(-1),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceState {
    pub ssid: Option<String>,
    pub state: Option<String>,
    pub bssid: Option<String>,
}

/// Parse `netsh wlan show interface`.
pub fn show_interface() -> Result<InterfaceState> {
    let out = run_netsh(&["wlan", "show", "interface"])?;
    let txt = &out.stdout;
    // SSID line: absent entirely when disconnected
    let ssid_re = Regex::new(r"SSID\s*:\s*(.+)").unwrap();
    let state_re = Regex::new(r"状态\s*:\s*(.+)").unwrap();
    let bssid_re = Regex::new(r"BSSID\s*:\s*([0-9a-fA-F:]{17})").unwrap();
    Ok(InterfaceState {
        ssid: ssid_re
            .captures(txt)
            .map(|c| c[1].trim().to_string()),
        state: state_re
            .captures(txt)
            .map(|c| c[1].trim().to_string()),
        bssid: bssid_re
            .captures(txt)
            .map(|c| c[1].to_lowercase()),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInfo {
    pub ssid: String,
    pub bssid: Option<String>,
    pub channel: Option<String>,
    pub signal: Option<u32>,
    pub auth: Option<String>,
}

/// Parse `netsh wlan show networks mode=bssid` into a list of networks.
/// Same-SSID duplicates keep the first occurrence (matches Python behavior).
pub fn show_networks() -> Result<Vec<NetworkInfo>> {
    let out = run_netsh(&["wlan", "show", "networks", "mode=bssid"])?;
    parse_networks(&out.stdout)
}

pub fn parse_networks(txt: &str) -> Result<Vec<NetworkInfo>> {
    let bssid_re = Regex::new(r"BSSID 1\s*:\s*([0-9a-fA-F:]+)").unwrap();
    let chan_re = Regex::new(r"频道\s*:\s*(\d+)").unwrap();
    let chan_re_en = Regex::new(r"Channel\s*:\s*(\d+)").unwrap();
    let sig_re = Regex::new(r"信号\s*:\s*(\d+)%").unwrap();
    let sig_re_en = Regex::new(r"Signal\s*:\s*(\d+)%").unwrap();
    let auth_re = Regex::new(r"身份验证\s*:\s*(.+)").unwrap();
    let auth_re_en = Regex::new(r"Authentication\s*:\s*(.+)").unwrap();

    let mut nets: Vec<NetworkInfo> = Vec::new();
    // Split on numbered SSID headers: "SSID 1 : value" / "SSID 2 : value"
    let block_re = Regex::new(r"(?m)^SSID \d+ : (.*)$").unwrap();
    let mut positions: Vec<(usize, String)> = Vec::new();
    for cap in block_re.captures_iter(txt) {
        let m = cap.get(1).unwrap();
        positions.push((m.start(), m.as_str().trim().to_string()));
    }
    for (idx, (start, ssid_val)) in positions.iter().enumerate() {
        let end = positions
            .get(idx + 1)
            .map(|(s, _)| *s)
            .unwrap_or(txt.len());
        let body = &txt[*start..end];
        let key = if ssid_val.is_empty() { "(empty)".to_string() } else { ssid_val.clone() };
        if nets.iter().any(|n| n.ssid == key) {
            continue;
        }
        let channel = chan_re
            .captures(body)
            .or_else(|| chan_re_en.captures(body))
            .map(|c| c[1].to_string());
        let signal = sig_re
            .captures(body)
            .or_else(|| sig_re_en.captures(body))
            .and_then(|c| c[1].parse::<u32>().ok());
        let auth = auth_re
            .captures(body)
            .or_else(|| auth_re_en.captures(body))
            .map(|c| c[1].trim().to_string());
        nets.push(NetworkInfo {
            ssid: key,
            bssid: bssid_re.captures(body).map(|c| c[1].to_lowercase()),
            channel,
            signal,
            auth,
        });
    }
    Ok(nets)
}

/// Connect to a saved profile (or any visible SSID with a profile).
pub fn connect(name: &str) -> Result<NetshOutput> {
    run_netsh(&["wlan", "connect", &format!("name={}", name)])
}

pub fn disconnect() -> Result<NetshOutput> {
    run_netsh(&["wlan", "disconnect"])
}

/// Export all saved profiles with passwords -> returns (name, password) pairs.
pub fn export_profiles() -> Result<Vec<(String, String)>> {
    let out = run_netsh(&["wlan", "show", "profile"])?;
    let name_re = Regex::new(r"所有用户配置文件\s*:\s*(.+)").unwrap();
    let name_re_en = Regex::new(r"All User Profile\s*:\s*(.+)").unwrap();
    let key_re = Regex::new(r"关键内容\s*:\s*(.+)").unwrap();
    let key_re_en = Regex::new(r"Key Content\s*:\s*(.+)").unwrap();

    let mut names: Vec<String> = Vec::new();
    for cap in name_re.captures_iter(&out.stdout) {
        names.push(cap[1].trim().to_string());
    }
    if names.is_empty() {
        for cap in name_re_en.captures_iter(&out.stdout) {
            names.push(cap[1].trim().to_string());
        }
    }

    let mut result = Vec::new();
    for name in names {
        let detail = run_netsh(&[
            "wlan",
            "show",
            "profile",
            &format!("name={}", name),
            "key=clear",
        ])?;
        let pw = key_re
            .captures(&detail.stdout)
            .or_else(|| key_re_en.captures(&detail.stdout))
            .map(|c| c[1].trim().to_string())
            .unwrap_or_else(|| "(none)".into());
        result.push((name, pw));
    }
    Ok(result)
}
