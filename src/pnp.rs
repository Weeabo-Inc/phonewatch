//! PnP device enumeration for phone target detection.
//!
//! Strategy (chosen after measurement, see README "How devices are enumerated"):
//!
//! * `SetupAPI` via `windows-sys` -> enumerates the present device tree in ~80-100 ms
//!   in-process, no child process, no admin rights.
//! * `Get-PnpDevice` via a hidden `powershell -NoProfile -Command ... | ConvertTo-Json`
//!   -> ~1250 ms wall clock per call (PowerShell startup + 45 KB of JSON).
//!
//! `SetupAPI` is therefore the primary path. A cross-check flag (`--pnp-cross-check`)
//! additionally runs the PowerShell path once at startup and reports any discrepancy,
//! so the fast path is verifiable against the tool the operator already trusts.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDevicePropertyW, SetupDiGetDeviceRegistryPropertyW,
    CM_Get_DevNode_Status, CR_NO_SUCH_DEVINST, CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT,
    HDEVINFO, SP_DEVINFO_DATA, SPDRP_CLASS, SPDRP_DEVICEDESC, SPDRP_DRIVER,
    SPDRP_ENUMERATOR_NAME, SPDRP_FRIENDLYNAME, SPDRP_MFG, SPDRP_SERVICE,
};
// `windows-sys` keeps `DEVPROPKEY` in `Win32::Devices::Properties` (0.52/0.59);
// it only moved to `Win32::Foundation` in 0.60+.
use windows_sys::Win32::Devices::Properties::DEVPROPKEY;
use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;

// ---------------------------------------------------------------------------
// Target matching rules
// ---------------------------------------------------------------------------

// CONVENTION - every `VID_`/`PID_` token in this module KEEPS its Windows prefix:
// `"VID_04E8"`, `"PID_6860"`. That is exactly what `extract_id` pulls out of a PnP
// instance id and what `Device::vid` / `Device::pid` are serialized as, and it is
// what `main.rs::derive_mode` consumes (it compares `pid` against `"PID_685D"` /
// `"PID_6860"`). The USB descriptor-failure id `VID_0000&PID_0002` follows the same
// rule. Do not mix bare and prefixed tokens here: doing so silently made every
// comparison below false, so a healthy phone was reported as absent.

/// `VID_04E8` (Samsung) with these PIDs is treated as "the target phone".
pub const SAMSUNG_VID: &str = "VID_04E8";
pub const SAMSUNG_PIDS: &[&str] = &[
    "PID_685D", // download / Odin mode
    "PID_6860", // MTP / ADB composite
    "PID_6601", // modem / diag
    "PID_68C3", // MTP+ADB composite (alternate)
    "PID_68EF", // CDC composite
    "PID_4EEE", // Samsung CDC serial
    "PID_4EEF", // Samsung CDC serial (alt)
];

/// `VID_18D1` (Google) => fastboot / Android composite.
pub const GOOGLE_VID: &str = "VID_18D1";

/// `VID_0000&PID_0002` => the USB device failed to hand back a descriptor.
pub const DESCRIPTOR_FAIL_VID: &str = "VID_0000";
pub const DESCRIPTOR_FAIL_PID: &str = "PID_0002";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Node reports OK / no problem code.
    Ok,
    /// `VID_0000&PID_0002` or CM problem code 43 (CM_PROB_FAILED_POST_START):
    /// the host could not read the device descriptor.
    DescriptorFailed,
    /// Present but in any other error state.
    Error,
    /// Present, but the node did not report a usable status.
    Unknown,
}

impl DeviceState {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceState::Ok => "ok",
            DeviceState::DescriptorFailed => "descriptor_failed",
            DeviceState::Error => "error",
            DeviceState::Unknown => "unknown",
        }
    }
}

/// Explanation of why a device was flagged as interesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReason {
    SamsungVid,
    GoogleVid,
    DescriptorFailureId,
    UsbPresent,
}

impl MatchReason {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchReason::SamsungVid => "samsung_vid",
            MatchReason::GoogleVid => "google_vid",
            MatchReason::DescriptorFailureId => "descriptor_failure_instance_id",
            MatchReason::UsbPresent => "usb_present",
        }
    }
}

/// One possibly-interesting device, flattened for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// `"USB\VID_04E8&PID_6860\R3CT..."` etc. Lowercased verbatim from Windows.
    pub instance_id: String,
    /// `"OK"` or `"Error"` - the same vocabulary `Get-PnpDevice` uses.
    pub status: String,
    /// Derived, machine-usable state.
    pub state: DeviceState,
    /// PnP class, e.g. `"USB"`, `"USBDevice"`, `"Ports"`, `"AndroidUsbDeviceClass"`.
    pub class: Option<String>,
    /// `FriendlyName` when the driver supplies one.
    pub friendly_name: Option<String>,
    /// Device description from the driver INF - present even when FriendlyName is not.
    pub device_desc: Option<String>,
    /// Manufacturer string from the INF.
    pub manufacturer: Option<String>,
    /// Upper-case VID extracted from the instance id, when present.
    pub vid: Option<String>,
    /// Upper-case PID extracted from the instance id, when present.
    pub pid: Option<String>,
    /// Function/driver service bound to the node (e.g. `WinUSB`, `usbccgp`, `Modem`).
    pub service: Option<String>,
    /// `SPDRP_DRIVER` value: the `...\Class\{GUID}\NNNN` driver key. Used to read the
    /// driver provider from the registry.
    pub driver_key: Option<String>,
    /// Driver provider, e.g. `"Samsung Electronics Co., Ltd."`, `"Microsoft"`.
    /// Read from `DEVPKEY_Device_DriverProvider` (registry fallback). `null` when the
    /// node has no driver (which is itself the interesting signal).
    pub driver_provider: Option<String>,
    /// `CM_Get_DevNode_Status` problem code (`CM_PROB_*`). `0` == no problem.
    pub problem_code: Option<u32>,
    /// Raw `CM_Get_DevNode_Status` / `SPDRP_PROBLEMCODE` value as Windows reports it.
    pub problem_code_raw: Option<u32>,
    /// `CM_Get_DevNode_Status` status bitfield, when available.
    pub devnode_status: Option<u32>,
    /// True when `devnode_status` has `DN_HAS_PROBLEM` (0x00000400) set.
    pub has_problem: Option<bool>,
    /// Human sentence for the problem code when it is a known one.
    pub problem_text: Option<String>,
    /// Which rule flagged this device.
    pub matched_by: MatchReason,
    /// Best display name: friendly_name -> device_desc -> instance_id.
    pub display_name: String,
    /// All non-empty string properties we gathered, for dashboard drill-down.
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbSummary {
    /// How the snapshot was produced.
    pub enumerated_by: String,
    /// Wall-clock cost of enumeration, milliseconds.
    pub enumerate_ms: u64,
    /// Total present nodes walked (all classes).
    pub total_present_nodes: usize,
    /// Present nodes whose instance id begins with `USB\` or `USBSTOR\`.
    pub usb_devices_present: usize,
    /// Filter applied to `matched`.
    pub filter: String,
    /// Devices that matched the filter.
    pub matched: Vec<Device>,
}

impl UsbSummary {
    pub fn matched_count(&self) -> usize {
        self.matched.len()
    }
}

// ---------------------------------------------------------------------------
// Property keys
// ---------------------------------------------------------------------------

/// `{a45c254e-df1c-4efd-8020-67d146a850e0}` - `DEVPKEY_Device_*`.
const GUID_DEVICE: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0xa45c_254e,
    data2: 0xdf1c,
    data3: 0x4efd,
    data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
};

const fn devpropkey(pid: u32) -> DEVPROPKEY {
    DEVPROPKEY {
        fmtid: GUID_DEVICE,
        pid,
    }
}

const DEVPKEY_DEVICE_DRIVER_PROVIDER: DEVPROPKEY = devpropkey(10);
const DEVPKEY_DEVICE_PROBLEM_CODE: DEVPROPKEY = devpropkey(13);
const DEVPKEY_DEVICE_DEVTYPE: DEVPROPKEY = devpropkey(19);
const DEVPKEY_DEVICE_ENUMERATOR_NAME: DEVPROPKEY = devpropkey(24);
const DEVPKEY_DEVICE_SERVICE: DEVPROPKEY = devpropkey(30);

const DEVPROP_TYPE_STRING: u32 = 0x0000_0012;
const DEVPROP_TYPE_UINT32: u32 = 0x0000_0007;
const DEVPROP_TYPE_GUID: u32 = 0x0000_000D;

const DN_HAS_PROBLEM: u32 = 0x0000_0400;

/// `CM_PROB_FAILED_POST_START` (code 43): the driver reported the device as failed
/// after start. This is the code Windows shows for "Device Descriptor Request Failed".
const CM_PROB_FAILED_POST_START: u32 = 43;

// `spdrp` values not re-exported by every windows-sys version.
const SPDRP_DEVICEDESC_U: u32 = SPDRP_DEVICEDESC as u32;
const SPDRP_CLASS_U: u32 = SPDRP_CLASS as u32;
const SPDRP_FRIENDLYNAME_U: u32 = SPDRP_FRIENDLYNAME as u32;
const SPDRP_MFG_U: u32 = SPDRP_MFG as u32;
const SPDRP_SERVICE_U: u32 = SPDRP_SERVICE as u32;
const SPDRP_DRIVER_U: u32 = SPDRP_DRIVER as u32;
const SPDRP_ENUMERATOR_NAME_U: u32 = SPDRP_ENUMERATOR_NAME as u32;

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct RawNode {
    instance_id: String,
    friendly_name: Option<String>,
    device_desc: Option<String>,
    class: Option<String>,
    manufacturer: Option<String>,
    service: Option<String>,
    driver_key: Option<String>,
    enumerator: Option<String>,
    spdrp_problem: Option<u32>,
    devnode_status: Option<u32>,
    devnode_problem: Option<u32>,
    has_problem: Option<bool>,
    driver_provider: Option<String>,
    devtype: Option<String>,
}

/// Enumerate every *present* device node. Requires no privileges.
pub fn enumerate_present() -> Result<Vec<RawNode>> {
    unsafe {
        let set = SetupDiGetClassDevsW(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_ALLCLASSES,
        );
        // INVALID_HANDLE_VALUE (-1) and null are both failures.
        // NOTE: `HDEVINFO` is `isize` in every windows-sys release (0.52 .. 0.61),
        // so it has no `is_null()` method.
        if set == 0 || set == -1 {
            return Err(anyhow!(
                "SetupDiGetClassDevsW failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut nodes = Vec::with_capacity(256);
        let mut index: u32 = 0;
        loop {
            let mut info: SP_DEVINFO_DATA = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

            if SetupDiEnumDeviceInfo(set, index, &mut info) == 0 {
                let err = std::io::Error::last_os_error();
                let code = err.raw_os_error().unwrap_or(0) as u32;
                if code == ERROR_NO_MORE_ITEMS {
                    break;
                }
                // Any other failure: stop rather than spin.
                break;
            }
            index += 1;

            let mut node = RawNode::default();

            // Instance ID
            let mut buf = [0u16; 1024];
            let mut required: u32 = 0;
            if SetupDiGetDeviceInstanceIdW(set, &mut info, buf.as_mut_ptr(), buf.len() as u32, &mut required) != 0
            {
                node.instance_id = u16z_to_string(&buf);
            }
            if node.instance_id.is_empty() {
                continue;
            }

            node.friendly_name = get_reg_string(set, &info, SPDRP_FRIENDLYNAME_U);
            node.device_desc = get_reg_string(set, &info, SPDRP_DEVICEDESC_U);
            node.class = get_reg_string(set, &info, SPDRP_CLASS_U);
            node.manufacturer = get_reg_string(set, &info, SPDRP_MFG_U);
            node.service = get_reg_string(set, &info, SPDRP_SERVICE_U);
            node.driver_key = get_reg_string(set, &info, SPDRP_DRIVER_U);
            node.enumerator = get_reg_string(set, &info, SPDRP_ENUMERATOR_NAME_U);
            // Windows exposes no `SPDRP_PROBLEMCODE`; the device problem code is the
            // `DEVPKEY_Device_ProblemCode` property (the CM_* code below wins anyway).
            node.spdrp_problem = get_prop_u32(set, &info, &DEVPKEY_DEVICE_PROBLEM_CODE);

            node.driver_provider = get_prop_string(set, &info, &DEVPKEY_DEVICE_DRIVER_PROVIDER);
            node.devtype = get_prop_string(set, &info, &DEVPKEY_DEVICE_DEVTYPE);
            // Touch the other keys so they are exercised, but prefer the CFGMGR32 codes.
            let _ = get_prop_string(set, &info, &DEVPKEY_DEVICE_ENUMERATOR_NAME);
            let _ = get_prop_string(set, &info, &DEVPKEY_DEVICE_SERVICE);
            let _ = get_prop_guid(set, &info);

            // CFGMGR32 status - authoritative problem code + status bitfield.
            let mut status: u32 = 0;
            let mut problem: u32 = 0;
            let cr = CM_Get_DevNode_Status(&mut status, &mut problem, info.DevInst, 0);
            if cr == CR_SUCCESS {
                node.devnode_status = Some(status);
                node.devnode_problem = Some(problem);
                node.has_problem = Some(status & DN_HAS_PROBLEM != 0);
            } else if cr == CR_NO_SUCH_DEVINST {
                node.devnode_status = None;
            }

            node.driver_provider = match node.driver_provider {
                Some(p) if !p.trim().is_empty() => Some(p),
                _ => driver_provider_from_registry(node.driver_key.as_deref()),
            };

            nodes.push(node);
        }

        SetupDiDestroyDeviceInfoList(set);
        Ok(nodes)
    }
}

unsafe fn get_reg_string(set: HDEVINFO, info: &SP_DEVINFO_DATA, prop: u32) -> Option<String> {
    let mut buf = [0u8; 4096];
    let mut required: u32 = 0;
    let ok = SetupDiGetDeviceRegistryPropertyW(
        set,
        info,
        prop,
        std::ptr::null_mut(),
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut required,
    );
    if ok == 0 {
        return None;
    }
    let bytes = buf.as_slice();
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let s = u16z_to_string(&units);
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn get_prop_string(
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    key: &DEVPROPKEY,
) -> Option<String> {
    let mut buf = [0u8; 4096];
    let mut required: u32 = 0;
    let mut prop_type: u32 = 0;
    let ok = SetupDiGetDevicePropertyW(
        set,
        info,
        key,
        &mut prop_type,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut required,
        0,
    );
    if ok == 0 || prop_type != DEVPROP_TYPE_STRING {
        return None;
    }
    let mut units: Vec<u16> = Vec::with_capacity(buf.len() / 2);
    for chunk in buf.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let s = u16z_to_string(&units);
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn get_prop_u32(
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    key: &DEVPROPKEY,
) -> Option<u32> {
    let mut value: u32 = 0;
    let mut required: u32 = 0;
    let mut prop_type: u32 = 0;
    let ok = SetupDiGetDevicePropertyW(
        set,
        info,
        key,
        &mut prop_type,
        &mut value as *mut u32 as *mut u8,
        std::mem::size_of::<u32>() as u32,
        &mut required,
        0,
    );
    if ok == 0 || prop_type != DEVPROP_TYPE_UINT32 {
        None
    } else {
        Some(value)
    }
}

unsafe fn get_prop_guid(set: HDEVINFO, info: &SP_DEVINFO_DATA) -> Option<[u8; 16]> {
    // DEVPKEY_Device_ClassGuid (pid 7)
    let key = devpropkey(7);
    let mut value = [0u8; 16];
    let mut required: u32 = 0;
    let mut prop_type: u32 = 0;
    let ok = SetupDiGetDevicePropertyW(
        set,
        info,
        &key,
        &mut prop_type,
        value.as_mut_ptr(),
        value.len() as u32,
        &mut required,
        0,
    );
    if ok == 0 || prop_type != DEVPROP_TYPE_GUID {
        None
    } else {
        Some(value)
    }
}

fn u16z_to_string(units: &[u16]) -> String {
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

// ---------------------------------------------------------------------------
// Driver provider fallback (registry)
// ---------------------------------------------------------------------------

/// `SPDRP_DRIVER` is `...\Class\{GUID}\NNNN`; the driver provider lives in
/// `HKLM\SYSTEM\CurrentControlSet\Control\Class\{GUID}\NNNN` value `ProviderName`.
/// Used only when `DEVPKEY_Device_DriverProvider` is unavailable.
fn driver_provider_from_registry(driver_key: Option<&str>) -> Option<String> {
    let key = driver_key?;
    let tail = key.rsplit("\\Class\\").next()?;
    if tail == key {
        return None;
    }
    let path = format!("SYSTEM\\CurrentControlSet\\Control\\Class\\{tail}");
    let value = reg_read_string(&path, "ProviderName")?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn reg_read_string(subkey: &str, name: &str) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_SZ, REG_EXPAND_SZ,
    };

    let wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let rc = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(subkey).as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );
        if rc != 0 {
            return None;
        }
        let mut ty: u32 = 0;
        let mut size: u32 = 4096;
        let mut buf = [0u8; 4096];
        let rc = RegQueryValueExW(
            hkey,
            wide(name).as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut size,
        );
        RegCloseKey(hkey);
        if rc != 0 || (ty != REG_SZ && ty != REG_EXPAND_SZ) {
            return None;
        }
        let mut units: Vec<u16> = Vec::with_capacity(size as usize / 2);
        for chunk in buf[..size as usize].chunks_exact(2) {
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        let s = u16z_to_string(&units);
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

// ---------------------------------------------------------------------------
// COM port mapping (registry) - no admin required
// ---------------------------------------------------------------------------

/// Read `HKLM\HARDWARE\DEVICEMAP\SERIALCOMM`: a map of
/// `\Device\Serial0` -> `COM1`. This is what `Win32_SerialPort` is built from.
pub fn serial_comm_map() -> Result<BTreeMap<String, String>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let mut out = BTreeMap::new();
    unsafe {
        let sub = std::ffi::OsStr::new("HARDWARE\\DEVICEMAP\\SERIALCOMM")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let mut hkey: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return Ok(out);
        }

        let mut i: u32 = 0;
        loop {
            let mut name = [0u16; 512];
            let mut name_len: u32 = name.len() as u32;
            let mut ty: u32 = 0;
            let mut data = [0u8; 1024];
            let mut data_len: u32 = data.len() as u32;
            let rc = RegEnumValueW(
                hkey,
                i,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut ty,
                data.as_mut_ptr(),
                &mut data_len,
            );
            if rc != 0 {
                break;
            }
            i += 1;
            if ty != REG_SZ {
                continue;
            }
            let device = u16z_to_string(&name[..name_len as usize]);
            let mut units: Vec<u16> = Vec::with_capacity(data_len as usize / 2);
            for chunk in data[..data_len as usize].chunks_exact(2) {
                units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            let port = u16z_to_string(&units);
            if !port.trim().is_empty() {
                // Skip the always-present built-in COM1 unless a device maps to it.
                out.insert(device, port);
            }
        }
        RegCloseKey(hkey);
    }
    Ok(out)
}

/// `Win32_SerialPort` view via CIM (slower, opt-in). Returns `(DeviceID, Description, PNPDeviceID)`.
pub fn serial_ports_wmi() -> Result<Vec<(String, String, String)>> {
    let script = "Get-CimInstance -ClassName Win32_SerialPort -ErrorAction SilentlyContinue | \
                  Select-Object DeviceID,Description,PNPDeviceID,Status | ConvertTo-Json -Compress -Depth 2";
    let raw = run_hidden_powershell(script)?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let arr = match value {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };
    let get = |v: &serde_json::Value, k: &str| -> String {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    Ok(arr
        .iter()
        .map(|v| {
            (
                get(v, "DeviceID"),
                get(v, "Description"),
                get(v, "PNPDeviceID"),
            )
        })
        .collect())
}

// ---------------------------------------------------------------------------
// PowerShell helper (used for opt-in cross-checks only)
// ---------------------------------------------------------------------------

/// Run a PowerShell snippet in a hidden, profile-less child process.
pub fn run_hidden_powershell(script: &str) -> Result<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    // CREATE_NO_WINDOW so no console flashes on a developer workstation.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("powershell exited with {}: {}", out.status, err.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `Get-PnpDevice` view of the targets, for cross-checking the SetupAPI path.
pub fn pnp_devices_powershell() -> Result<Vec<serde_json::Value>> {
    let script = "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | \
                  Select-Object Status,Class,FriendlyName,InstanceId,Problem,ProblemDescription,Service | \
                  ConvertTo-Json -Compress -Depth 3";
    let raw = run_hidden_powershell(script)?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(raw)?;
    Ok(match value {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    })
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

pub struct EnumerateOptions {
    /// Include every present USB node, not just the phone targets.
    pub all_usb: bool,
    pub cross_check: bool,
}

/// Full device probe: enumerate, classify, optionally cross-check.
pub fn probe(opts: &EnumerateOptions) -> Result<UsbSummary> {
    let started = std::time::Instant::now();
    let nodes = enumerate_present()?;
    let enumerate_ms = started.elapsed().as_millis() as u64;

    let total_present_nodes = nodes.len();
    let usb_nodes: Vec<&RawNode> = nodes
        .iter()
        .filter(|n| is_usb_node(&n.instance_id))
        .collect();
    let usb_devices_present = usb_nodes.len();

    let mut matched: Vec<Device> = Vec::new();
    for node in &usb_nodes {
        if let Some(m) = classify(node, opts.all_usb) {
            matched.push(m);
        }
    }
    // Stable order: errors first (they are what the dashboard must surface), then by id.
    matched.sort_by(|a, b| {
        state_rank(a.state)
            .cmp(&state_rank(b.state))
            .then_with(|| a.instance_id.cmp(&b.instance_id))
    });

    if opts.cross_check {
        cross_check(&matched);
    }

    Ok(UsbSummary {
        enumerated_by: "windows-setupapi (SetupDiGetClassDevs + CM_Get_DevNode_Status)".to_string(),
        enumerate_ms,
        total_present_nodes,
        usb_devices_present,
        filter: if opts.all_usb {
            "all present USB/USBSTOR nodes".to_string()
        } else {
            "VID_04E8(PID in 685D,6860,6601,68C3,68EF,4EEE,4EEF) | VID_18D1 | VID_0000&PID_0002".to_string()
        },
        matched,
    })
}

fn state_rank(s: DeviceState) -> u8 {
    match s {
        DeviceState::DescriptorFailed => 0,
        DeviceState::Error => 1,
        DeviceState::Unknown => 2,
        DeviceState::Ok => 3,
    }
}

fn is_usb_node(instance_id: &str) -> bool {
    let up = instance_id.to_ascii_uppercase();
    up.starts_with("USB\\") || up.starts_with("USBSTOR\\")
}

/// Parse a `VID_`/`PID_` token out of a PnP instance id, **keeping its prefix**.
///
/// A Windows instance id is `Enumerator\HardwareId\InstanceSpecific`, e.g.
/// `USB\VID_04E8&PID_6860&MI_00\7&1F2A3B4C&0&0000`. Only the *second* component may
/// be scanned: the trailing per-instance part (serial, port path, ...) is full of
/// `&` and hex digits and would otherwise be swallowed into the token. Within the
/// hardware id the tokens are `&`-separated (`VID_04E8`, `PID_6860`, `MI_00`, ...).
///
/// Returns the token *with* its prefix, per the convention documented above the
/// target-matching constants: `extract_id("USB\\VID_04E8&PID_6860\\R3CT123", "VID_")`
/// is `Some("VID_04E8")`.
fn extract_id(instance_id: &str, prefix: &str) -> Option<String> {
    let up = instance_id.to_ascii_uppercase();
    // Second component only; if the id is not `A\B\...`, fall back to the whole string.
    let hardware_id = up.split('\\').nth(1).unwrap_or(up.as_str());
    hardware_id
        .split('&')
        .find(|tok| tok.starts_with(prefix))
        .map(|tok| tok.to_string())
}

/// Decide whether a node is a target and, if so, turn it into a `Device`.
fn classify(node: &RawNode, all_usb: bool) -> Option<Device> {
    let vid = extract_id(&node.instance_id, "VID_");
    let pid = extract_id(&node.instance_id, "PID_");
    let vid_s = vid.clone().unwrap_or_default();
    let pid_s = pid.clone().unwrap_or_default();

    // Conflict rule: the Windows-reported problem code wins over the registry value,
    // because that is the code `Get-PnpDevice`'s Problem/Status columns reflect.
    let effective_problem = node
        .devnode_problem
        .or(node.spdrp_problem)
        .filter(|c| *c != 0);

    let descriptor_failure = (vid_s == DESCRIPTOR_FAIL_VID && pid_s == DESCRIPTOR_FAIL_PID)
        || effective_problem == Some(CM_PROB_FAILED_POST_START);

    let samsung = vid_s == SAMSUNG_VID && SAMSUNG_PIDS.contains(&pid_s.as_str());
    let google = vid_s == GOOGLE_VID;

    let matched_by = if descriptor_failure {
        Some(MatchReason::DescriptorFailureId)
    } else if samsung {
        Some(MatchReason::SamsungVid)
    } else if google {
        Some(MatchReason::GoogleVid)
    } else if all_usb {
        Some(MatchReason::UsbPresent)
    } else {
        None
    }?;

    let state = if descriptor_failure {
        DeviceState::DescriptorFailed
    } else {
        match (node.has_problem, effective_problem) {
            (Some(true), _) => DeviceState::Error,
            (_, Some(_)) => DeviceState::Error,
            (Some(false), None) => DeviceState::Ok,
            (None, None) => {
                // No CM status and no problem code: fall back to the SPDRP value.
                match node.spdrp_problem {
                    Some(0) => DeviceState::Ok,
                    Some(_) => DeviceState::Error,
                    None => DeviceState::Unknown,
                }
            }
        }
    };

    let display_name = node
        .friendly_name
        .clone()
        .or_else(|| node.device_desc.clone())
        .unwrap_or_else(|| node.instance_id.clone());

    let mut properties: BTreeMap<String, String> = BTreeMap::new();
    let mut put = |k: &str, v: &Option<String>| {
        if let Some(v) = v {
            if !v.trim().is_empty() {
                properties.insert(k.to_string(), v.clone());
            }
        }
    };
    put("instance_id", &Some(node.instance_id.clone()));
    put("friendly_name", &node.friendly_name);
    put("device_desc", &node.device_desc);
    put("class", &node.class);
    put("manufacturer", &node.manufacturer);
    put("service", &node.service);
    put("driver_key", &node.driver_key);
    put("driver_provider", &node.driver_provider);
    put("enumerator", &node.enumerator);
    put("devtype", &node.devtype);
    if let Some(v) = &vid {
        properties.insert("vid".to_string(), v.clone());
    }
    if let Some(v) = &pid {
        properties.insert("pid".to_string(), v.clone());
    }

    Some(Device {
        instance_id: node.instance_id.clone(),
        status: match state {
            DeviceState::Ok => "OK".to_string(),
            DeviceState::Unknown => "Unknown".to_string(),
            _ => "Error".to_string(),
        },
        state,
        class: node.class.clone(),
        friendly_name: node.friendly_name.clone(),
        device_desc: node.device_desc.clone(),
        manufacturer: node.manufacturer.clone(),
        vid,
        pid,
        service: node.service.clone(),
        driver_key: node.driver_key.clone(),
        driver_provider: node.driver_provider.clone(),
        problem_code: effective_problem,
        problem_code_raw: node.devnode_problem.or(node.spdrp_problem),
        devnode_status: node.devnode_status,
        has_problem: node.has_problem,
        problem_text: effective_problem.map(problem_text),
        matched_by,
        display_name,
        properties,
    })
}

/// Human sentence for the `CM_PROB_*` codes that matter for this monitor.
pub fn problem_text(code: u32) -> String {
    let name = match code {
        0 => "CM_PROB_NONE",
        1 => "CM_PROB_NOT_CONFIGURED",
        3 => "CM_PROB_OUT_OF_MEMORY",
        10 => "CM_PROB_FAILED_START",
        12 => "CM_PROB_NORMAL_CONFLICT",
        14 => "CM_PROB_NEED_RESTART",
        18 => "CM_PROB_REINSTALL",
        19 => "CM_PROB_REGISTRY",
        21 => "CM_PROB_WILL_BE_REMOVED",
        22 => "CM_PROB_DISABLED",
        24 => "CM_PROB_DEVICE_NOT_THERE",
        28 => "CM_PROB_FAILED_INSTALL",
        43 => "CM_PROB_FAILED_POST_START",
        45 => "CM_PROB_DISABLED_SERVICE",
        48 => "CM_PROB_BLOCKED_SAFELY",
        _ => "CM_PROB_UNKNOWN",
    };
    if code == CM_PROB_FAILED_POST_START {
        format!(
            "{name} ({}): the USB device did not return a descriptor - Windows shows \
             \"Device Descriptor Request Failed\" (Code 43)",
            code
        )
    } else {
        format!("{name} ({code})")
    }
}

/// Compare the SetupAPI result against `Get-PnpDevice` and print any disagreement.
fn cross_check(matched: &[Device]) {
    println!("--- pnp cross-check (Get-PnpDevice) ---");
    match pnp_devices_powershell() {
        Ok(rows) => {
            let mut ps: Vec<(String, String)> = Vec::new();
            for r in &rows {
                let iid = r
                    .get("InstanceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if !is_usb_node(&iid) {
                    continue;
                }
                // Mirror `classify` exactly: the cross-check pool must use the same
                // target predicate as the SetupAPI side, otherwise a Samsung node
                // with an unlisted PID shows up as a spurious "SetupAPI missed ...".
                let vid = extract_id(&iid, "VID_").unwrap_or_default();
                let pid = extract_id(&iid, "PID_").unwrap_or_default();
                let is_target = (vid == SAMSUNG_VID && SAMSUNG_PIDS.contains(&pid.as_str()))
                    || vid == GOOGLE_VID
                    || (vid == DESCRIPTOR_FAIL_VID && pid == DESCRIPTOR_FAIL_PID);
                if is_target {
                    let status = r
                        .get("Status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown");
                    ps.push((iid, status.to_string()));
                }
            }
            println!("Get-PnpDevice target rows: {}", ps.len());
            for (iid, status) in &ps {
                println!("  {status:8} {iid}");
            }
            println!("SetupAPI target rows:     {}", matched.len());
            for d in matched {
                println!("  {:8} {}", d.status, d.instance_id);
            }
            let ps_ids: Vec<&String> = ps.iter().map(|(i, _)| i).collect();
            let sa_ids: Vec<&String> = matched.iter().map(|d| &d.instance_id).collect();
            let missing: Vec<&&String> = ps_ids.iter().filter(|i| !sa_ids.contains(i)).collect();
            if missing.is_empty() {
                println!("agreement: OK (every Get-PnpDevice target row was found by SetupAPI)");
            } else {
                println!("DISAGREEMENT: SetupAPI missed {missing:?}");
            }
        }
        Err(e) => println!("cross-check skipped: {e:#}"),
    }
    println!("--- end cross-check ---");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_extracted() {
        // Tokens keep their `VID_`/`PID_` prefix (module convention).
        assert_eq!(
            extract_id("USB\\VID_04E8&PID_6860\\R3CT123", "VID_").as_deref(),
            Some("VID_04E8")
        );
        // The serial after the second `\` must NOT leak into the token.
        assert_eq!(
            extract_id("USB\\VID_04E8&PID_6860\\R3CT123", "PID_").as_deref(),
            Some("PID_6860")
        );
        // Composite interface id: the trailing `&`-laden port path must be ignored.
        assert_eq!(
            extract_id("USB\\VID_04E8&PID_6860&MI_00\\7&1F2A3B4C&0&0000", "PID_").as_deref(),
            Some("PID_6860")
        );
        assert_eq!(extract_id("USB\\ROOT_HUB30\\5&4087", "VID_"), None);
        // A `VID_`-looking string in the per-instance part must not be picked up.
        assert_eq!(extract_id("USB\\ROOT_HUB30\\5&VID_9999", "VID_"), None);
    }

    #[test]
    fn usb_nodes_are_recognised() {
        assert!(is_usb_node("USB\\VID_04E8&PID_685D\\X"));
        assert!(is_usb_node("usbstor\\disk&ven_x\\1"));
        assert!(!is_usb_node("HID\\VID_05AC&PID_024F"));
    }

    #[test]
    fn descriptor_failure_wins_classification() {
        let node = RawNode {
            instance_id: "USB\\VID_0000&PID_0002\\5&1&0&1".to_string(),
            devnode_problem: Some(43),
            has_problem: Some(true),
            ..Default::default()
        };
        let d = classify(&node, false).expect("must match");
        assert_eq!(d.state, DeviceState::DescriptorFailed);
        assert_eq!(d.status, "Error");
        assert_eq!(d.matched_by, MatchReason::DescriptorFailureId);
    }

    #[test]
    fn samsung_pid_set_matches() {
        // Uses a realistic instance id (serial after the second `\`), so it also
        // guards the `\`-termination half of the extract_id bug.
        let node = RawNode {
            instance_id: "USB\\VID_04E8&PID_6860\\R3CT123".to_string(),
            devnode_problem: Some(0),
            has_problem: Some(false),
            ..Default::default()
        };
        let d = classify(&node, false).expect("must match");
        assert_eq!(d.state, DeviceState::Ok);
        assert_eq!(d.matched_by, MatchReason::SamsungVid);
        assert_eq!(d.vid.as_deref(), Some("VID_04E8"));
        assert_eq!(d.pid.as_deref(), Some("PID_6860"));
    }

    /// Regression: `extract_id` used to strip the `VID_`/`PID_` prefix and stop only
    /// at `&`, so every comparison against the (prefixed) target constants was false
    /// and a healthy phone was silently reported as absent by the dashboard.
    #[test]
    fn regression_healthy_targets_are_matched() {
        // Healthy Samsung MTP/ADB composite -> SamsungVid.
        let samsung = RawNode {
            instance_id: "USB\\VID_04E8&PID_6860\\R3CT123".to_string(),
            devnode_problem: Some(0),
            has_problem: Some(false),
            ..Default::default()
        };
        let d = classify(&samsung, false).expect("healthy Samsung MTP node must match");
        assert_eq!(d.matched_by, MatchReason::SamsungVid);
        assert_eq!(d.state, DeviceState::Ok);
        assert_eq!(d.pid.as_deref(), Some("PID_6860"));

        // Healthy Google / fastboot -> GoogleVid.
        let google = RawNode {
            instance_id: "USB\\VID_18D1&PID_4EE7\\X1".to_string(),
            devnode_problem: Some(0),
            has_problem: Some(false),
            ..Default::default()
        };
        let g = classify(&google, false).expect("healthy Google/fastboot node must match");
        assert_eq!(g.matched_by, MatchReason::GoogleVid);
        assert_eq!(g.state, DeviceState::Ok);

        // Bare descriptor-failure id, with NO CM problem code to fall back on.
        let failed = RawNode {
            instance_id: "USB\\VID_0000&PID_0002\\5&1&0&1".to_string(),
            ..Default::default()
        };
        let f = classify(&failed, false).expect("VID_0000&PID_0002 node must match");
        assert_eq!(f.matched_by, MatchReason::DescriptorFailureId);
        assert_eq!(f.state, DeviceState::DescriptorFailed);

        // And a Samsung node whose PID is not in the list must still be ignored.
        let unknown = RawNode {
            instance_id: "USB\\VID_04E8&PID_9999\\R3CT123".to_string(),
            devnode_problem: Some(0),
            has_problem: Some(false),
            ..Default::default()
        };
        assert!(classify(&unknown, false).is_none());
    }

    #[test]
    fn unknown_samsung_pid_is_ignored_by_default() {
        let node = RawNode {
            instance_id: "USB\\VID_04E8&PID_9999\\7&1".to_string(),
            devnode_problem: Some(0),
            has_problem: Some(false),
            ..Default::default()
        };
        assert!(classify(&node, false).is_none());
        assert!(classify(&node, true).is_some());
    }
}
