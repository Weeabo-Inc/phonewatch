//! phonewatch - live Windows device-state monitor.
//!
//! Polls USB/PnP state of the target phone (Samsung Galaxy A13 / SM-A135F) and writes:
//!   * a single atomically-replaced JSON snapshot  (default `state.json`)
//!   * an append-only JSONL history                (default `history.jsonl`)
//!
//! The dashboard at <REPO_ROOT>\dashboard serves that JSON on
//! http://127.0.0.1:8787 and re-renders it live.
//!
//! Honesty notes:
//!   * Every field is best-effort. Anything undeterminable is `null`/empty, never faked.
//!   * `adb` polling is OFF by default: libwdi's INF stamps the download-mode node with
//!     the *ADB interface GUID*, so merely starting the adb server can steal the very
//!     WinUSB handle another client needs. Opt in with `--adb`.

mod pnp;

use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use pnp::{DeviceState, EnumerateOptions};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_STATE: &str = r"<REPO_ROOT>\phonewatch\state.json";
const DEFAULT_HISTORY: &str = r"<REPO_ROOT>\phonewatch\history.jsonl";
const DEFAULT_INTERVAL_MS: u64 = 2000;
const DEFAULT_LAN: &str = "<LAN_IP>:8022";
const DEFAULT_HISTORY_MAX: usize = 5000;

const ADB_EXE: &str =
    r"<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe";

/// Processes known to grab a USB handle on this machine.
const HANDLE_HOLDERS: &[&str] = &["zadig", "brokkr", "scrcpy", "odin", "heimdall", "odin-probe"];

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcInfo {
    name: String,
    pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComPort {
    name: String,
    device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdbInfo {
    polled: bool,
    state: Option<String>,
    raw: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LanInfo {
    target: String,
    reachable: bool,
    latency_ms: Option<u128>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    seq: u64,
    timestamp: String,
    mode: String,
    phone_present: bool,
    primary: Option<Value>,
    devices: Vec<Value>,
    usb: Value,
    com_ports: Vec<ComPort>,
    adb: AdbInfo,
    lan: LanInfo,
    processes: Vec<ProcInfo>,
    warnings: Vec<String>,
    interval_ms: u64,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Opts {
    state: PathBuf,
    history: PathBuf,
    interval_ms: u64,
    lan: String,
    adb: bool,
    all_usb: bool,
    once: bool,
    history_max: usize,
}

fn parse_args() -> Opts {
    let mut o = Opts {
        state: PathBuf::from(DEFAULT_STATE),
        history: PathBuf::from(DEFAULT_HISTORY),
        interval_ms: DEFAULT_INTERVAL_MS,
        lan: DEFAULT_LAN.to_string(),
        adb: false,
        all_usb: false,
        once: false,
        history_max: DEFAULT_HISTORY_MAX,
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        let take = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match a.as_str() {
            "--state" => {
                if let Some(v) = take(&mut i) {
                    o.state = PathBuf::from(v);
                }
            }
            "--history" => {
                if let Some(v) = take(&mut i) {
                    o.history = PathBuf::from(v);
                }
            }
            "--interval-ms" | "--interval" => {
                if let Some(v) = take(&mut i) {
                    o.interval_ms = v.parse().unwrap_or(DEFAULT_INTERVAL_MS).max(250);
                }
            }
            "--lan" => {
                if let Some(v) = take(&mut i) {
                    o.lan = v;
                }
            }
            "--adb" => o.adb = true,
            "--all-usb" => o.all_usb = true,
            "--once" => o.once = true,
            "--history-max" => {
                if let Some(v) = take(&mut i) {
                    o.history_max = v.parse().unwrap_or(DEFAULT_HISTORY_MAX);
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => eprintln!("phonewatch: ignoring unknown argument {other:?} (try --help)"),
        }
        i += 1;
    }
    o
}

fn print_help() {
    println!(
        "phonewatch - live device-state monitor\n\n\
USAGE:\n  phonewatch [OPTIONS]\n\n\
OPTIONS:\n\
\x20 --state <PATH>       JSON snapshot output     (default {DEFAULT_STATE})\n\
\x20 --history <PATH>     JSONL history output     (default {DEFAULT_HISTORY})\n\
\x20 --interval-ms <N>    poll period, min 250     (default {DEFAULT_INTERVAL_MS})\n\
\x20 --lan <HOST:PORT>    TCP reachability target  (default {DEFAULT_LAN})\n\
\x20 --adb                ALSO poll `adb devices`  (OFF by default: adb steals the USB handle)\n\
\x20 --all-usb            include every present USB node, not just phone targets\n\
\x20 --history-max <N>    trim history beyond N rows (default {DEFAULT_HISTORY_MAX})\n\
\x20 --once               take one snapshot and exit\n\
\x20 -h, --help           this text"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_iso8601() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let millis = d.subsec_millis();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 -> civil date (Howard Hinnant's civil_from_days)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Atomically replace `path` with `contents` (write temp, then rename).
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f =
            fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn append_line(path: &Path, line: &str) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

fn trim_history(path: &Path, max: usize) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() <= max {
        return;
    }
    let joined = format!("{}\n", lines[lines.len() - max..].join("\n"));
    let _ = write_atomic(path, &joined);
}

/// Find processes that could be holding a USB handle.
///
/// A process merely *existing* is not enough to be a threat. A terminated-but-
/// unreaped process (a zombie) still shows up in `tasklist` and in
/// `Get-Process`, yet has zero threads and an empty executable path — it cannot
/// execute an instruction, let alone own a device handle. We have been bitten by
/// exactly that: a ghost `brokkr` produced a permanent false warning.
///
/// So we require BOTH:
///   * at least one thread, and
///   * a non-empty executable path,
/// which excludes zombies while keeping genuine handle-holders.
fn running_handle_holders() -> Vec<ProcInfo> {
    let mut out = Vec::new();

    // Ask PowerShell for name/pid/path/thread-count. -NoProfile keeps it fast;
    // this costs a process spawn per poll, so the interval should not be tiny.
    // The name alternation is built from HANDLE_HOLDERS so the list stays single-sourced.
    let alternation = HANDLE_HOLDERS
        .iter()
        .map(|h| regex_escape(h))
        .collect::<Vec<_>>()
        .join("|");
    let script = format!(
        "Get-Process -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.ProcessName -match '^({alternation})$' }} | \
         Select-Object ProcessName,Id,Path,@{{n='Threads';e={{$_.Threads.Count}}}} | \
         ConvertTo-Json -Compress"
    );

    let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    else {
        return out;
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return out;
    }

    // ConvertTo-Json emits a bare object for a single result, an array for many.
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let rows: Vec<&Value> = match &value {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![&value],
        _ => Vec::new(),
    };

    for row in rows {
        let name = row
            .get("ProcessName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let pid = row.get("Id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let threads = row
            .get("Threads")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let path = row.get("Path").and_then(|v| v.as_str()).unwrap_or("");
        let is_zombie = threads <= 0 || path.is_empty();

        if !is_zombie {
            out.push(ProcInfo { name, pid });
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.pid == b.pid);
    out
}

/// Escape a literal for safe embedding in a PowerShell `-match` alternation.
///
/// The inputs are our own compile-time constants, but escaping keeps this correct
/// if someone later adds a name with a regex metacharacter in it.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\^$.[]|()?*+{}-".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn com_ports() -> Vec<ComPort> {
    match pnp::serial_comm_map() {
        Ok(map) => map
            .into_iter()
            .map(|(name, device)| ComPort { name, device })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn adb_probe(enabled: bool) -> AdbInfo {
    if !enabled {
        return AdbInfo {
            polled: false,
            state: None,
            raw: None,
            error: None,
        };
    }
    if !Path::new(ADB_EXE).exists() {
        return AdbInfo {
            polled: true,
            state: None,
            raw: None,
            error: Some(format!("adb not found at {ADB_EXE}")),
        };
    }
    match Command::new(ADB_EXE).args(["devices", "-l"]).output() {
        Ok(o) => {
            let raw = String::from_utf8_lossy(&o.stdout).to_string();
            let state = raw
                .lines()
                .skip(1)
                .find(|l| l.trim().len() > 8)
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|s| s.to_string());
            AdbInfo {
                polled: true,
                state,
                raw: Some(raw),
                error: None,
            }
        }
        Err(e) => AdbInfo {
            polled: true,
            state: None,
            raw: None,
            error: Some(e.to_string()),
        },
    }
}

fn lan_probe(target: &str) -> LanInfo {
    let Some((host, port)) = target.rsplit_once(':') else {
        return LanInfo {
            target: target.to_string(),
            reachable: false,
            latency_ms: None,
            error: Some("target must be HOST:PORT".into()),
        };
    };
    let Ok(port) = port.parse::<u16>() else {
        return LanInfo {
            target: target.to_string(),
            reachable: false,
            latency_ms: None,
            error: Some("bad port".into()),
        };
    };
    let ip = host
        .parse::<IpAddr>()
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(700)) {
        Ok(_) => LanInfo {
            target: target.to_string(),
            reachable: true,
            latency_ms: Some(started.elapsed().as_millis()),
            error: None,
        },
        Err(e) => LanInfo {
            target: target.to_string(),
            reachable: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
    }
}

/// Collapse matched devices into one headline mode string.
fn derive_mode(matched: &[pnp::Device]) -> (String, Option<usize>) {
    if matched.is_empty() {
        return ("absent".to_string(), None);
    }
    if let Some(idx) = matched
        .iter()
        .position(|d| d.state == DeviceState::DescriptorFailed)
    {
        return ("descriptor_failed".to_string(), Some(idx));
    }
    if let Some(idx) = matched.iter().position(|d| {
        d.pid
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case("PID_685D"))
    }) {
        return ("download".to_string(), Some(idx));
    }
    if let Some(idx) = matched.iter().position(|d| {
        d.pid
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case("PID_6860"))
    }) {
        return ("mtp_or_adb".to_string(), Some(idx));
    }
    (matched[0].state.as_str().to_string(), Some(0))
}

// ---------------------------------------------------------------------------
// One snapshot
// ---------------------------------------------------------------------------

fn take_snapshot(seq: u64, o: &Opts) -> Result<Snapshot> {
    let summary = pnp::probe(&EnumerateOptions {
        all_usb: o.all_usb,
        cross_check: true,
    })?;

    let (mode, primary_idx) = derive_mode(&summary.matched);
    let primary = primary_idx
        .and_then(|i| summary.matched.get(i))
        .and_then(|d| serde_json::to_value(d).ok());
    let devices: Vec<Value> = summary
        .matched
        .iter()
        .filter_map(|d| serde_json::to_value(d).ok())
        .collect();

    let com = com_ports();
    let procs = running_handle_holders();

    let mut warnings = Vec::new();
    if mode == "descriptor_failed" {
        warnings.push(
            "USB Device Descriptor Request Failed: Windows cannot read the phone's descriptors, \
             so no driver can bind and no client can talk to it."
                .to_string(),
        );
    }
    if mode == "absent" {
        warnings.push(
            "No matching USB device present (unplugged, powered off, or not enumerated)."
                .to_string(),
        );
    }
    for p in &procs {
        if p.name == "zadig" || p.name == "brokkr" {
            warnings.push(format!(
                "{} (pid {}) may hold a WinUSB handle, blocking other clients.",
                p.name, p.pid
            ));
        }
    }
    if o.adb && procs.iter().any(|p| p.name == "adb") {
        warnings.push(
            "adb is running with --adb polling on: libwdi stamps the node with the ADB interface \
             GUID, so adb can steal the handle."
                .to_string(),
        );
    }

    Ok(Snapshot {
        seq,
        timestamp: now_iso8601(),
        mode,
        phone_present: !summary.matched.is_empty(),
        primary,
        devices,
        usb: json!({
            "enumerated_by": summary.enumerated_by,
            "enumerate_ms": summary.enumerate_ms,
            "total_present_nodes": summary.total_present_nodes,
            "usb_devices_present": summary.usb_devices_present,
            "matched_count": summary.matched_count(),
            "filter": summary.filter,
        }),
        com_ports: com,
        adb: adb_probe(o.adb),
        lan: lan_probe(&o.lan),
        processes: procs,
        warnings,
        interval_ms: o.interval_ms,
    })
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let o = parse_args();

    println!("phonewatch - live device-state monitor");
    println!("  state   : {}", o.state.display());
    println!("  history : {}", o.history.display());
    println!("  interval: {} ms", o.interval_ms);
    println!("  lan     : {}", o.lan);
    println!(
        "  adb poll: {}",
        if o.adb { "ON (may steal the USB handle!)" } else { "off" }
    );
    println!();

    let mut seq: u64 = 0;
    loop {
        seq += 1;
        match take_snapshot(seq, &o) {
            Ok(snap) => {
                let j = serde_json::to_string_pretty(&snap)?;
                if let Err(e) = write_atomic(&o.state, &j) {
                    eprintln!("phonewatch: writing state failed: {e:#}");
                }
                if let Ok(line) = serde_json::to_string(&snap) {
                    append_line(&o.history, &line);
                }
                if seq % 50 == 0 {
                    trim_history(&o.history, o.history_max);
                }

                let svc = snap
                    .primary
                    .as_ref()
                    .and_then(|p| p.get("service"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let ports: Vec<&str> = snap.com_ports.iter().map(|c| c.name.as_str()).collect();
                let procs: Vec<&str> = snap.processes.iter().map(|p| p.name.as_str()).collect();
                println!(
                    "[{:>5}] mode={:<17} devs={:<2} svc={:<12} com=[{}] procs=[{}] lan={} warn={}",
                    snap.seq,
                    snap.mode,
                    snap.devices.len(),
                    svc,
                    ports.join(","),
                    procs.join(","),
                    if snap.lan.reachable { "up" } else { "down" },
                    snap.warnings.len()
                );
            }
            Err(e) => eprintln!("phonewatch: snapshot failed: {e:#}"),
        }

        if o.once {
            break;
        }
        std::thread::sleep(Duration::from_millis(o.interval_ms));
    }
    Ok(())
}
