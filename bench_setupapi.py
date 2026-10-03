import ctypes, ctypes.wintypes as w, time, json

setupapi = ctypes.WinDLL('setupapi')
cfgmgr = ctypes.WinDLL('cfgmgr32')

DIGCF_PRESENT = 0x02
DIGCF_ALLCLASSES = 0x04
SPDRP_DEVICEDESC = 0x00
SPDRP_CLASS = 0x07
SPDRP_CLASSGUID = 0x08
SPDRP_FRIENDLYNAME = 0x0C
SPDRP_ENUMERATOR_NAME = 0x16
SPDRP_PROBLEMCODE = 0x1C
SPDRP_SERVICE = 0x04
SPDRP_DRIVER = 0x09
SPDRP_MFG = 0x0B

class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [("cbSize", w.DWORD), ("ClassGuid", ctypes.c_byte*16),
                ("DevInst", w.DWORD), ("Reserved", ctypes.POINTER(ctypes.c_ulong))]

setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.c_void_p, w.LPCWSTR, w.HWND, w.DWORD]
setupapi.SetupDiEnumDeviceInfo.argtypes = [ctypes.c_void_p, w.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]
setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD)]

def getprop(h, did, prop):
    buf = ctypes.create_unicode_buffer(1024)
    need = w.DWORD(0)
    ok = setupapi.SetupDiGetDeviceRegistryPropertyW(h, ctypes.byref(did), prop, None, buf, ctypes.sizeof(buf), ctypes.byref(need))
    return buf.value if ok else None

def enumerate():
    h = setupapi.SetupDiGetClassDevsW(None, None, None, DIGCF_PRESENT | DIGCF_ALLCLASSES)
    if h == ctypes.c_void_p(-1).value or not h:
        return []
    out = []
    i = 0
    while True:
        did = SP_DEVINFO_DATA()
        did.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
        if not setupapi.SetupDiEnumDeviceInfo(ctypes.c_void_p(h), i, ctypes.byref(did)):
            break
        i += 1
        iid = ctypes.create_unicode_buffer(512)
        setupapi.SetupDiGetDeviceInstanceIdW(ctypes.c_void_p(h), ctypes.byref(did), iid, 512, None)
        out.append({
            "instanceId": iid.value,
            "friendlyName": getprop(h, did, SPDRP_FRIENDLYNAME),
            "deviceDesc": getprop(h, did, SPDRP_DEVICEDESC),
            "class": getprop(h, did, SPDRP_CLASS),
            "service": getprop(h, did, SPDRP_SERVICE),
            "problem": getprop(h, did, SPDRP_PROBLEMCODE),
        })
    setupapi.SetupDiDestroyDeviceInfoList(ctypes.c_void_p(h))
    return out

for n in range(3):
    t = time.perf_counter()
    devs = enumerate()
    ms = (time.perf_counter() - t) * 1000
    print(f"run{n}: {len(devs)} devices in {ms:.1f} ms")

targets = [d for d in devs if d["instanceId"] and ("VID_04E8" in d["instanceId"] or "VID_18D1" in d["instanceId"] or "VID_0000" in d["instanceId"])]
print("targets:", json.dumps(targets, indent=1))
with open("bench_setupapi_out.json", "w", encoding="utf-8") as f:
    json.dump(devs, f, indent=1)
