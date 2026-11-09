//! Offline crack: aircrack-ng.exe against .cap files.
//!
//! Word sources, tried in order per capture (stop at first KEY FOUND):
//!   1. pattern generator via stdin (`-w -`): common numerics, dates, pinyin
//!      combos, optionally the full 8-digit numeric space (100M)
//!   2. every dictionary file found in config (dict + dicts_dir/*.txt|dic|lst)
//!
//! Progress lines from aircrack ("[00:01:12] 123/456 keys tested") are forwarded
//! as events; a hard timeout kills the process.

use anyhow::Result;
use serde::Serialize;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::CrackCfg;
use crate::pipeline::EventTx;

#[derive(Debug, Clone, Serialize)]
pub struct CrackResult {
    pub cap: String,
    pub cracked: bool,
    pub password: Option<String>,
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extract the key from aircrack output. Aircrack 1.7 prints:
///   KEY FOUND! [ thekey ]
/// Cascade: bracket after KEY FOUND marker -> colon form -> per-line bracket.
fn extract_key(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    if !lower.contains("key found") {
        return None;
    }
    let re1 = regex::Regex::new(r"(?i)key found[^\[]*\[\s*([^\]]+)\s*\]").unwrap();
    if let Some(c) = re1.captures(text) {
        return Some(c[1].trim().to_string());
    }
    let re2 = regex::Regex::new(r"(?i)key found.*?:\s*(\S+)").unwrap();
    if let Some(c) = re2.captures(text) {
        return Some(c[1].trim().to_string());
    }
    for line in text.lines() {
        if line.to_lowercase().contains("key found") {
            let re3 = regex::Regex::new(r"\[([^\]]+)\]").unwrap();
            if let Some(c) = re3.captures(line) {
                return Some(c[1].trim().to_string());
            }
        }
    }
    None
}

/// Absolute path without the \\?\ prefix (Cygwin-friendly): relative paths
/// resolve against OUR cwd, not the child's (aircrack runs with cwd=acng_bin).
fn abs(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

/// Probe the first target BSSID in a capture (aircrack lists networks when
/// run without -w). stdin mode (`-w -`) refuses to auto-select a network,
/// so this is required before streaming candidates.
fn probe_bssid(acng_bin: &Path, cap: &Path) -> Option<String> {
    let out = Command::new(acng_bin.join("aircrack-ng.exe"))
        .arg(abs(cap))
        .current_dir(acng_bin)
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        crate::netsh::decode_gbk(&out.stdout),
        crate::netsh::decode_gbk(&out.stderr)
    );
    let re = regex::Regex::new(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b").ok()?;
    re.captures(&text).map(|c| c[0].to_lowercase())
}

/// Run aircrack for one capture with either a dict file (`dict_arg` = path)
/// or candidates streamed to stdin (`dict_arg` == "-").
fn run_aircrack(
    acng_bin: &Path,
    cap: &Path,
    dict_arg: &Path,
    candidates: Option<Box<dyn Iterator<Item = String> + Send>>,
    _tx: Option<&EventTx>,
    timeout: Duration,
) -> Result<String> {
    let exe = acng_bin.join("aircrack-ng.exe");
    if !exe.exists() {
        anyhow::bail!("aircrack-ng.exe not found in {}", acng_bin.display());
    }
    let cap_abs = abs(cap);
    let dict_abs = if dict_arg == Path::new("-") {
        PathBuf::from("-")
    } else {
        abs(dict_arg)
    };
    let mut cmd = Command::new(&exe);
    cmd.arg("-a").arg("2").arg("-w").arg(&dict_abs);
    if dict_abs == PathBuf::from("-") {
        // stdin wordlist requires an explicit network selection
        if let Some(bssid) = probe_bssid(acng_bin, cap) {
            tracing::info!("crack: stdin mode target bssid={}", bssid);
            cmd.arg("-b").arg(&bssid);
        }
    }
    cmd.arg(&cap_abs);
    cmd.current_dir(acng_bin) // Cygwin DLLs live here
        .stdin(if candidates.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;

    // stdin writer thread (pattern mode)
    let writer = candidates.map(|cands| {
        let stdin = child.stdin.take().expect("stdin piped");
        std::thread::spawn(move || {
            let mut buf = BufWriter::with_capacity(1 << 20, stdin);
            for c in cands {
                if buf.write_all(c.as_bytes()).is_err() || buf.write_all(b"\n").is_err() {
                    break; // pipe closed (process died / killed)
                }
            }
            let _ = buf.flush();
            drop(buf); // EOF so aircrack finishes the last candidates
        })
    });

    // stdout reader: collect text + forward progress events
    let stdout = child.stdout.take().expect("stdout piped");
    let reader_out = std::thread::spawn(move || collect_output(stdout));
    // stderr reader: collect error text
    let stderr = child.stderr.take().expect("stderr piped");
    let reader_err = std::thread::spawn(move || collect_output(stderr));

    // timeout enforcement
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        let done = writer.as_ref().map(|w| w.is_finished()).unwrap_or(true)
            && reader_out.is_finished()
            && reader_err.is_finished();
        if done {
            break;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    let out = reader_out.join().unwrap_or_default();
    let err = reader_err.join().unwrap_or_default();
    if let Some(w) = writer {
        let _ = w.join();
    }
    let _ = child.wait();
    if timed_out {
        anyhow::bail!("TIMEOUT after {}s", timeout.as_secs());
    }
    Ok(format!("{}{}", out, err))
}

/// Read a child stream, splitting on \r and \n (aircrack redraws progress with \r),
/// forwarding "N/M keys tested" percentages as events.
fn collect_output<R: Read + Send + 'static>(mut r: R) -> String {
    let mut text = String::new();
    let mut last_percent_step = 0u32;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
        // Process complete lines/segments
        while let Some(pos) = buf.iter().position(|&b| b == b'\n' || b == b'\r') {
            let seg_bytes: Vec<u8> = buf.drain(..=pos).collect();
            let seg = String::from_utf8_lossy(&seg_bytes[..pos]);
            text.push_str(&seg);
            text.push('\n');
            {
                if seg.contains("keys tested") {
                    if let Some(c) = regex::Regex::new(r"\]\s*(\d+)/(\d+)")
                        .ok()
                        .and_then(|re| re.captures(&seg))
                    {
                        let done: u64 = c[1].parse().unwrap_or(0);
                        let total: u64 = c[2].parse().unwrap_or(1);
                        let percent = (done * 100 / total.max(1)) as u32;
                        if percent / 10 > last_percent_step {
                            last_percent_step = percent / 10;
                            tracing::info!("crack 进度: {}% ({}/{})", percent, done, total);
                        }
                    }
                }
            }
        }
    }
    if !buf.is_empty() {
        text.push_str(&String::from_utf8_lossy(&buf));
    }
    text
}

// ── pattern dictionary ──────────────────────────────────────────────────────

const COMMON: &[&str] = &[
    "12345678", "123456789", "1234567890", "87654321", "987654321", "9876543210",
    "11111111", "00000000", "22222222", "33333333", "55555555", "66666666",
    "77777777", "88888888", "99999999", "12121212", "11223344", "12341234",
    "12344321", "12346578", "12365478", "147258369", "258369147", "369258147",
    "159357462", "135792468", "1357924680", "1029384756", "123123123", "456456456",
    "111222333", "777888999", "123456789a", "123456789q", "a123456789", "aa123456",
    "abcd1234", "abc12345", "qwer1234", "1q2w3e4r", "1qaz2wsx", "qazwsxedc",
    "520520", "5201314", "1314520", "520131400", "13145200", "5211314",
    "13800138000", "13911011011", "18600000000", "123698745", "321654987",
    "password", "password1", "admin123", "qwerty123", "a12345678", "zxcvbn123",
];

const PINYIN: &[&str] = &[
    "woaini", "aini", "wo", "ni", "wang", "li", "zhang", "chen", "liu", "yang",
    "huang", "zhao", "wu", "zhou", "xu", "sun", "ma", "zhu", "hu", "guo",
    "lin", "he", "gao", "luo", "zheng", "liang", "xie", "song", "tang", "han",
    "feng", "deng", "cao", "peng", "zeng", "xiao", "tian", "dong", "yuan", "pan",
    "yu", "jiang", "cai", "jia", "du", "ye", "cheng", "su", "wei", "lu",
    "mima", "guanli", "jiayou", "kuaile", "xingfu", "meili", "yonggan",
    "aishang", "xiangni", "aini1314", "yongheng", "weila", "zhongguo",
    "shanghai", "beijing", "shenzhen", "hangzhou", "suzhou", "nanjing",
    "wuxi", "kunshan", "changzhou", "nantong", "yangzhou", "jiayuan",
    "aimei", "qiankun", "tianxia", "wansui", "caishen", "facai", "fugui",
    "jinbao", "pingan", "shunli", "ruyi", "meihao", "zhaocai", "jixiang",
    "qingwa", "xiaobai", "dahuang", "keai", "baobao", "nainai", "yeye",
    "mama", "baba", "gege", "didi", "jiejie", "meimei", "laopo", "laogong",
    "xiansheng", "shenghuo", "gongzuo", "xuexi", "dian nao", "shouji",
    "wangluo", "mimaji", "woshizhu", "nihaoma", "chifanle", "shuijiao",
];

const PINYIN_SUFFIX: &[&str] = &[
    "", "1", "12", "123", "1234", "12345", "123456", "520", "521", "666",
    "888", "999", "000", "111", "1314", "2020", "2023", "2024", "2025", "2026",
];

/// Built-in pattern candidates: common -> dates(1900-2026) -> pinyin combos,
/// and (full8) the whole 8-digit numeric space 00000000..99999999.
pub fn pattern_candidates(full8: bool) -> Box<dyn Iterator<Item = String> + Send> {
    let mut v: Vec<String> = Vec::with_capacity(60_000);
    for c in COMMON {
        v.push((*c).to_string());
    }
    for y in 1900..=2026u32 {
        for m in 1..=12u32 {
            let max_d = match m {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                _ => {
                    if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 }
                }
            };
            for d in 1..=max_d {
                v.push(format!("{}{:02}{:02}", y, m, d));
            }
        }
    }
    for w in PINYIN {
        for s in PINYIN_SUFFIX {
            v.push(format!("{}{}", w, s));
        }
    }
    if !full8 {
        return Box::new(v.into_iter());
    }
    Box::new(v.into_iter().chain((0u64..100_000_000).map(|n| format!("{:08}", n))))
}

// ── crack orchestration ─────────────────────────────────────────────────────

fn result_from(cap_name: &str, text: &str, source: &str) -> CrackResult {
    match extract_key(text) {
        Some(key) => {
            tracing::info!("crack: *** CRACKED {} -> {} (source: {}) ***", cap_name, key, source);
            CrackResult {
                cap: cap_name.into(),
                cracked: true,
                password: Some(key),
                source: Some(source.into()),
                timed_out: None,
                error: None,
            }
        }
        None => {
            tracing::info!("crack: not cracked: {} (source: {})", cap_name, source);
            CrackResult {
                cap: cap_name.into(),
                cracked: false,
                password: None,
                source: Some(source.into()),
                timed_out: None,
                error: None,
            }
        }
    }
}

/// Crack one capture with one dictionary file.
pub fn crack_one_file(acng_bin: &Path, cap: &Path, dict: &Path, timeout: Duration) -> Result<CrackResult> {
    let name = cap.file_name().unwrap_or_default().to_string_lossy().to_string();
    let src = dict.file_name().unwrap_or_default().to_string_lossy().to_string();
    tracing::info!("crack: aircrack-ng -a 2 -w {} {}", src, name);
    let text = run_aircrack(acng_bin, cap, dict, None, None, timeout)?;
    Ok(result_from(&name, &text, &src))
}

/// Crack one capture feeding built-in patterns over stdin.
pub fn crack_one_patterns(
    acng_bin: &Path,
    cap: &Path,
    full8: bool,
    _tx: Option<&EventTx>,
    timeout: Duration,
) -> Result<CrackResult> {
    let name = cap.file_name().unwrap_or_default().to_string_lossy().to_string();
    let src = if full8 { "patterns+full8" } else { "patterns" };
    tracing::info!("crack: aircrack-ng -a 2 -w - (stdin: {}) {}", src, name);
    if full8 {
        tracing::info!("crack: 模式字典（含全量8位数字 1 亿，耗时较长）…");
    } else {
        tracing::info!("crack: 模式字典（常用数字/日期/拼音，约 5 万）…");
    }
    let text = run_aircrack(
        acng_bin,
        cap,
        Path::new("-"),
        Some(pattern_candidates(full8)),
        None,
        timeout,
    )?;
    Ok(result_from(&name, &text, src))
}

/// Crack every .cap in caps_dir: patterns first, then each dict file; stop on success.
/// Crack an explicit list of cap files (session-aware callers use this).
pub fn crack_caps_files(
    acng_bin: &Path,
    caps: &[PathBuf],
    cfg: &CrackCfg,
    dicts: &[PathBuf],
    _tx: Option<&EventTx>,
) -> Result<Vec<CrackResult>> {
    let caps: Vec<PathBuf> = caps.to_vec();
    if caps.is_empty() {
        tracing::info!("crack: empty cap list — nothing to do");
        return Ok(Vec::new());
    }
    tracing::info!(
        "crack: {} cap(s), dicts: {} file(s), patterns={}, full8={}",
        caps.len(),
        dicts.len(),
        cfg.use_patterns,
        cfg.full8
    );

    let timeout = Duration::from_secs(cfg.timeout_sec.max(60));
    let mut results = Vec::new();
    for cap in &caps {
        let name = cap.file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut done: Option<CrackResult> = None;

        if cfg.use_patterns {
            match crack_one_patterns(acng_bin, cap, cfg.full8, None, timeout) {
                Ok(r) if r.cracked => done = Some(r),
                Ok(_) => {}
                Err(e) => tracing::warn!("crack: patterns on {}: {}", name, e),
            }
        }
        if done.is_none() {
            for dict in dicts {
                match crack_one_file(acng_bin, cap, dict, timeout) {
                    Ok(r) if r.cracked => {
                        done = Some(r);
                        break;
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::warn!("crack: {} with {}: {}", name, dict.display(), e);
                        if e.to_string().contains("TIMEOUT") {
                            tracing::info!("crack: {} 超时，跳过 {}", dict.display(), name);
                            continue;
                        }
                    }
                }
            }
        }
        results.push(done.unwrap_or(CrackResult {
            cap: name,
            cracked: false,
            password: None,
            source: None,
            timed_out: None,
            error: None,
        }));
    }
    let n = results.iter().filter(|r| r.cracked).count();
    tracing::info!("crack: done {}/{} cracked", n, results.len());
    Ok(results)
}

/// Legacy helper: crack every .cap directly inside one directory.
pub fn crack_caps(
    acng_bin: &Path,
    caps_dir: &Path,
    cfg: &CrackCfg,
    dicts: &[PathBuf],
    tx: Option<&EventTx>,
) -> Result<Vec<CrackResult>> {
    let mut caps: Vec<PathBuf> = Vec::new();
    if caps_dir.exists() {
        for entry in std::fs::read_dir(caps_dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("cap") {
                caps.push(p);
            }
        }
    }
    caps.sort();
    if caps.is_empty() {
        tracing::info!("crack: no .cap files in {} — nothing to do", caps_dir.display());
        return Ok(Vec::new());
    }
    crack_caps_files(acng_bin, &caps, cfg, dicts, tx)
}

/// Save results JSON to logs/crack_results.json.
pub fn save_result(res: &[CrackResult], logs_dir: &Path) -> Result<()> {
    let path = logs_dir.join("crack_results.json");
    let json = serde_json::to_string_pretty(res)?;
    std::fs::write(&path, json)?;
    tracing::info!("crack: results -> {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_key_found() {
        let t = "Aircrack-ng 1.7\n\nKEY FOUND! [ SuperSecret123 ]\n\n";
        assert_eq!(extract_key(t), Some("SuperSecret123".into()));
    }

    #[test]
    fn parses_legacy_key_found() {
        let t = "KEY FOUND: abc12345";
        assert_eq!(extract_key(t), Some("abc12345".into()));
    }

    #[test]
    fn no_key() {
        assert_eq!(extract_key("No keys found in capture"), None);
    }

    #[test]
    fn patterns_have_dates_and_pinyin() {
        let pats: Vec<String> = pattern_candidates(false).collect();
        assert!(pats.contains(&"20240101".to_string()));
        assert!(pats.contains(&"woaini520".to_string()));
        assert!(pats.contains(&"12345678".to_string()));
        // dates 1900-2026 valid only
        assert!(!pats.contains(&"20230230".to_string()));
        // ~60 common + ~46.4k dates + ~2.2k pinyin
        assert!(pats.len() > 40_000 && pats.len() < 80_000);
    }

    /// End-to-end against the committed aircrack-ng test vector:
    /// dicts/test/wpa.cap has passphrase "biscotte" (aircrack-ng test suite).
    #[test]
    fn end_to_end_wpa_cap_file_dict() {
        let acng = crate::config::Config::default().crack.acng_bin;
        let cap = PathBuf::from("dicts/test/wpa.cap");
        let dict = PathBuf::from("dicts/test/password.lst");
        if !acng.join("aircrack-ng.exe").exists() || !cap.exists() || !dict.exists() {
            return; // environment not available; skip silently
        }
        let r = crack_one_file(&acng, &cap, &dict, Duration::from_secs(120)).unwrap();
        assert!(r.cracked, "expected crack of wpa.cap, got {:?}", r);
        assert_eq!(r.password.as_deref(), Some("biscotte"));
    }

    /// Same capture, candidates streamed over stdin (`-w -`).
    #[test]
    fn end_to_end_wpa_cap_stdin() {
        let acng = crate::config::Config::default().crack.acng_bin;
        let cap = PathBuf::from("dicts/test/wpa.cap");
        if !acng.join("aircrack-ng.exe").exists() || !cap.exists() {
            return;
        }
        let cands: Box<dyn Iterator<Item = String> + Send> =
            Box::new(["wrongpass1", "biscotte", "wrongpass2"].iter().map(|s| s.to_string()));
        let text = run_aircrack(&acng, &cap, Path::new("-"), Some(cands), None, Duration::from_secs(120))
            .expect("stdin crack should run");
        assert_eq!(extract_key(&text).as_deref(), Some("biscotte"));
    }
}
