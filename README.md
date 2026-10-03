<div align="center">
	<img width=140 src="assets/cover.svg" />
	<h2>phonewatch</h2>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6.svg?style=flat-square)]()
[![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=flat-square)]()
[![Runtime deps](https://img.shields.io/badge/runtime%20deps-zero-brightgreen.svg?style=flat-square)]()

### Paranoid fast USB state tracking.

A live device-state monitor for Windows that tells you what your phone is actually doing, not what you hoped it was doing. It watches USB nodes, COM ports, and the processes that might be holding a handle open, then writes a JSON snapshot you can read, diff, or feed to a dashboard.

Written while trying to work out why a Galaxy A13 in Download Mode was invisible to every flashing tool on the machine. The answer turned out to be a host driver problem, and finding it required watching the device's state change in real time instead of inferring it from failed commands.

---

### What does this do?

Polls Windows for device state and reports it:

```
$ phonewatch --once
phonewatch - live device-state monitor
  state   : state.json
  history : history.jsonl
--- pnp cross-check (Get-PnpDevice) ---
Get-PnpDevice target rows: 0
SetupAPI target rows:     0
agreement: OK (every Get-PnpDevice target row was found by SetupAPI)
--- end cross-check ---
[    1] mode=absent   devs=0  svc=-  com=[\Device\Serial0] procs=[] lan=down warn=1
```

The modes it can tell apart:

| Mode | Meaning |
|---|---|
| `absent` | not on the bus at all |
| `download` | Download Mode (`04E8:685D`), the Odin/flash target |
| `mtp_or_adb` | normal Android (`04E8:6860`) |
| `descriptor_failed` | **electrically present, descriptors unreadable** (`0000:0002`) |
| `google` | fastboot or Android composite |

That fourth one is the reason this exists. `VID_0000&PID_0002` means Windows can see the device's electrical signature and cannot read its descriptors. No other tool names that state, and it looks identical to "unplugged" if you only check for known IDs.

---

### Two bugs worth reading about

Both of these shipped in early versions, and both looked like working software.

#### The prefix bug

```rust
extract_id() stripped the "VID_"/"PID_" prefix,
but classify() compared the STRIPPED value against the PREFIXED constants.

=> every comparison was false, permanently.
```

A healthy Samsung device was reported `absent` on every single poll. The descriptor-failure path still worked through a problem-code fallback, so the tool appeared functional while quietly lying about the main case.

`extract_id()` now parses instead of splitting naively. It takes only the second backslash-separated component (the hardware ID), splits that on `&`, and returns the token with its prefix intact. There is a regression test covering all three target classes.

#### The zombie bug

A terminated but unreaped process still shows up in `tasklist` and `Get-Process`, so an earlier version flagged a ghost `brokkr` as a USB handle risk forever.

A zombie has zero threads and an empty executable path. It cannot hold a handle. The check now requires both a non-empty path and at least one thread:

```rust
let is_zombie = threads <= 0 || path.is_empty();
```

The ghost was still there afterwards. The tool just stopped lying about it.

---

### How do I use it?

```powershell
cargo build --release
target\release\phonewatch.exe --once
```

| Flag | Default | Meaning |
|---|---|---|
| `--state PATH` | `state.json` | snapshot output |
| `--history PATH` | `history.jsonl` | rolling history |
| `--interval-ms N` | `2000` | poll interval |
| `--once` | off | single pass and exit |
| `--adb` | **off** | enable adb polling (see below) |

#### Why `--adb` is off by default

On Windows, `adb.exe` binds the Android interface GUID and will steal the handle from any other client. During this project that produced a real `libusb_open failed: Access (Access denied)` which took a while to identify. For USB work, run `adb kill-server` first and leave it dead.

---

### Output

| File | Contents |
|---|---|
| `state.json` | devices, COM ports, processes, LAN reachability, warnings |
| `history.jsonl` | append-only history, trimmed to a rolling window |

```json
{
  "mode": "descriptor_failed",
  "phone_present": false,
  "devices": [],
  "usb": { "enumerate_ms": 258, "total_present_nodes": 214, "usb_devices_present": 13 },
  "com_ports": [{ "name": "\\Device\\Serial0", "com": "COM1" }],
  "processes": [],
  "warnings": ["No matching USB device present (unplugged, powered off, or not enumerated)."]
}
```

The JSON is consumed by [**klabsat**](https://github.com/Weeabo-Inc/klabsat).

---

### How it works under the hood

#### SetupAPI, not PowerShell

`pnp.rs` (around 1000 lines) talks to SetupAPI through `windows-sys` rather than shelling out to `Get-PnpDevice`. Two reasons:

1. **Cross-checking.** It queries the same devices both ways and reports any disagreement. `agreement: OK` is a real assertion, not a print statement.
2. **Speed.** Enumerating 214 nodes in roughly 260 ms is fast enough to poll continuously. PowerShell cmdlets are not.

#### A note on windows-sys versions

`HDEVINFO` is `isize` in every release from 0.52 to 0.61, so `.is_null()` can never work on it. `DEVPROPKEY` moved from `Win32::Devices::Properties` to `Win32::Foundation` in 0.60 and later. This crate pins **0.59**, which is the last version where the existing code type-checks without a rewrite.

---

### What it can and can't do

**Can do:**
- Classify device mode, including the descriptor-failure state
- Map COM ports and attribute them to devices
- Identify processes holding USB handles, with zombie filtering
- Cross-check its own enumeration against a second API
- Emit machine-readable snapshots

**Can't do:**
- Flash, erase, or write anything to a device. It observes only.
- Run without SetupAPI, so this is Windows-only
- Recover a device whose descriptors are unreadable. It reports the state, it cannot fix it.

---

### Project layout

```
phonewatch/
├── assets/
│   └── cover.svg
├── src/
│   ├── main.rs        polling loop, state assembly, CLI
│   └── pnp.rs         SetupAPI enumeration, classification, cross-check
├── Cargo.toml
└── Cargo.lock
```

---

### Credits

- [windows-sys](https://github.com/microsoft/windows-rs) for the Win32 bindings
- [Twemoji](https://github.com/twitter/twemoji) for the cover art, CC BY 4.0
- The SetupAPI documentation, which is drier than this README

---

<div align="center">
	<br/>
	<i>read only by design. it watches, it does not touch.</i>
	<br/>
	<sub>built for a phone that would not talk to anything.</sub>
</div>
