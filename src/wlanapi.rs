//! Minimal runtime binding to wlanapi.dll: trigger an active WiFi scan.
//!
//! `netsh wlan show networks` only reads the OS's cached list — while connected,
//! the adapter rarely sweeps other channels, so the cache holds just the current
//! AP. `WlanScan` forces a full channel sweep (exactly what Windows does when you
//! open the WiFi flyout), refreshing that cache.
//!
//! Loaded via GetProcAddress so no import library is needed (works on MSVC and GNU).

use anyhow::{bail, Result};
use std::ffi::{c_void, CString};
use std::os::raw::c_char;

/// RTL_GUID layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

type WHandle = *mut c_void;

type WlanOpenHandleFn = unsafe extern "system" fn(u32, *mut c_void, *mut u32, *mut WHandle) -> u32;
type WlanCloseHandleFn = unsafe extern "system" fn(WHandle, *mut c_void) -> u32;
type WlanEnumInterfacesFn = unsafe extern "system" fn(WHandle, *mut c_void, *mut *mut c_void) -> u32;
type WlanScanFn = unsafe extern "system" fn(
    WHandle,
    *const Guid,
    *const c_void, // pDot11Ssid (NULL = all)
    *const c_void, // pIeData (NULL)
    *mut c_void,   // reserved
) -> u32;
type WlanFreeMemoryFn = unsafe extern "system" fn(*mut c_void);

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(name: *const c_char) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
}

struct WlanApi {
    open: WlanOpenHandleFn,
    close: WlanCloseHandleFn,
    enum_interfaces: WlanEnumInterfacesFn,
    scan: WlanScanFn,
    free: WlanFreeMemoryFn,
}

/// Offsets/strides confirmed against Windows SDK 10.0.19041 wlanapi.h:
/// WLAN_INTERFACE_INFO_LIST { DWORD dwNumberOfItems; DWORD dwIndex; entries[] }
/// WLAN_INTERFACE_INFO { GUID(16) + WCHAR[256](512) + WLAN_INTERFACE_STATE(4) } = 532 bytes
const LIST_HEADER: usize = 8;
const IFACE_ENTRY: usize = 532;

fn load() -> Result<WlanApi> {
    unsafe {
        let lib = LoadLibraryA(CString::new("wlanapi.dll")?.as_ptr());
        if lib.is_null() {
            bail!("wlanapi.dll could not be loaded");
        }
        let sym = |name: &str| -> Result<*mut c_void> {
            let p = GetProcAddress(lib, CString::new(name)?.as_ptr());
            if p.is_null() {
                bail!("wlanapi.dll export missing: {}", name);
            }
            Ok(p)
        };
        Ok(WlanApi {
            open: std::mem::transmute(sym("WlanOpenHandle")?),
            close: std::mem::transmute(sym("WlanCloseHandle")?),
            enum_interfaces: std::mem::transmute(sym("WlanEnumInterfaces")?),
            scan: std::mem::transmute(sym("WlanScan")?),
            free: std::mem::transmute(sym("WlanFreeMemory")?),
        })
    }
}

/// Trigger `WlanScan` on every WLAN interface. Returns how many interfaces accepted it.
/// Best-effort: failures are returned as Err but never affect the connection itself.
pub fn trigger_scan_all() -> Result<usize> {
    let api = load()?;
    unsafe {
        let mut negotiated: u32 = 0;
        let mut handle: WHandle = std::ptr::null_mut();
        // client version 2 = Vista+
        let rc = (api.open)(2, std::ptr::null_mut(), &mut negotiated, &mut handle);
        if rc != 0 {
            bail!("WlanOpenHandle failed, rc={}", rc);
        }
        let mut list: *mut c_void = std::ptr::null_mut();
        let rc = (api.enum_interfaces)(handle, std::ptr::null_mut(), &mut list);
        if rc != 0 || list.is_null() {
            (api.close)(handle, std::ptr::null_mut());
            bail!("WlanEnumInterfaces failed, rc={}", rc);
        }
        let count = *(list as *const u32);
        let entries = (list as *const u8).add(LIST_HEADER);
        let mut triggered = 0usize;
        for i in 0..count as usize {
            let guid = entries.add(i * IFACE_ENTRY) as *const Guid;
            let rc = (api.scan)(
                handle,
                guid,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            if rc == 0 {
                triggered += 1;
            } else {
                tracing::debug!("WlanScan rc={} on interface {}", rc, i);
            }
        }
        (api.free)(list);
        (api.close)(handle, std::ptr::null_mut());
        Ok(triggered)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn triggers_scan_on_at_least_one_interface() {
        // Harmless: forces the adapter to sweep channels (like opening the flyout).
        let n = super::trigger_scan_all().expect("wlanapi should load and scan");
        assert!(n >= 1, "expected at least 1 interface, got {}", n);
    }
}
