# phonewatch

**A live device-state monitor for Windows** — watches USB devices, COM ports, and
handle-holding processes, and tells you *what state your phone is actually in*.

Built while debugging why a Galaxy A13 in Download Mode was invisible to every flashing
tool. The answer turned out to be a host driver problem, and finding it required seeing the
device's state change in real time rather than inferring it from failed commands.

---

## What it does

Polls Windows for device state and writes a JSON snapshot you can watch, diff, or feed to a
dashboard:

```console
$ phonewatch --once
phonewatch - live device-state monitor
  state   : <REPO_ROOT>\phonewatch\state.json
  history : <REPO_ROOT>\phonewatch\history.jsonl
--- pnp cross-check (Get-PnpDevice) ---
Get-PnpDevice target rows: 0
SetupAPI target rows:     0
agreement: OK (every Get-PnpDevice target row was found by SetupAPI)
--- end cross-check ---
[    1] mode=absent            devs=0  svc=-            com=[\Device\Serial0] procs=[brokkr] lan=down warn=2
```

### Device modes it distinguishes

| Mode | Meaning |
|---|---|
| `absent` | not on the bus at all |
| `download` | Download Mode (`04E8:685D`) — Odin/flash target |
| `mtp_or_adb` | normal Android (`04E8:6860`) |
| `descriptor_failed` | **electrically present but descriptors unreadable** (`0000:0002`) |
| `google` | fastboot / Android composite |

That fourth one is why this exists. `VID_0000&PID_0002` means Windows sees the device's
electrical signature and **cannot read its descriptors** — a state no other tool names, and
one that looks identical to "unplugged" if you only check for known IDs.

---

## The bug worth reading about

An early version reported `absent` for a phone that was **sitting right there**.

```rust
extract_id() stripped the "VID_"/"PID_" prefix,
but classify() compared the STRIPPED value against the PREFIXED constants.

=> those comparisons could NEVER be true.
```

A healthy Samsung device was reported absent, every single time. The
descriptor-failure path still worked — via a problem-code fallback — so the tool
**appeared functional** while silently lying about the main case.

`extract_id()` now **parses** rather than splits naively: it takes only the second
`\`-separated component (the hardware ID), splits that on `&`, and returns the token *with*
its prefix. There's a regression test covering all three target classes.

**Lesson embedded in the code:** *a plausible-looking value is not a measured one.*

**Also embedded in the code:** a code comment that says, in full, *"A process merely
existing is not enough to be a threat."* Which is true of processes, and of most things.

### The zombie-process bug

A terminated-but-unreaped process still appears in `tasklist` and `Get-Process`, so an
earlier version flagged a ghost `brokkr` as a USB-handle risk **forever**.

A zombie has **zero threads** and an **empty executable path** — it cannot hold a handle.
It now requires *both* a non-empty path and at least one thread:

```rust
let is_zombie = threads <= 0 || path.is_empty();
```

The ghost was still there after the fix; the tool just stopped lying about it.

---

## Output

| File | Contents |
|---|---|
| `state.json` | current snapshot — devices, COM ports, processes, LAN reachability, warnings |
| `history.jsonl` | append-only history, trimmed to a rolling window |

The JSON is consumed by [**klabsat**](https://github.com/Weeabo-Inc/klabsat), the
companion dashboard.

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

---

## Why it uses SetupAPI directly

`pnp.rs` (~1000 lines) talks to SetupAPI via `windows-sys` rather than shelling out to
`Get-PnpDevice`, for two reasons:

1. **A cross-check.** It queries the same devices both ways and reports any disagreement —
   `agreement: OK` is a real assertion, not a print statement.
2. **Enumerating 214 nodes in ~260 ms** is fast enough to poll continuously, which
   PowerShell cmdlets are not.

**Note on `windows-sys` versions:** `HDEVINFO` is `isize` in *every* release (0.52–0.61),
so `.is_null()` can never work on it. And `DEVPROPKEY` moved from
`Win32::Devices::Properties` to `Win32::Foundation` in 0.60+. This crate pins **0.59**.

---

## Options

```
--state PATH       state.json output path
--history PATH     history.jsonl output path
--interval-ms N    poll interval (default 2000)
--once             single pass and exit
--adb              enable adb polling (default OFF — see below)
```

**`--adb` is off by default and that is deliberate.** On Windows, `adb.exe` binds the
Android interface GUID and will **steal the handle** from any other client. During this
project that caused a real `libusb_open failed: Access (Access denied)` that took a while to
identify. For USB work: `adb kill-server` first, and leave it dead.

---

## Building

```console
$ cargo build --release
$ cargo test --release
test result: ok. 6 passed; 0 failed
```

---

## Scope, honestly

**Solid:** device mode classification, descriptor-failure detection, COM port mapping,
process attribution with zombie filtering, SetupAPI/Get-PnpDevice cross-checking,
`state.json` / `history.jsonl` output.

**Deliberately not a flasher.** It observes and reports; it never writes to a device.

**Known limitation:** `adb` polling is opt-in because it conflicts with libusb clients.

## License

MIT
