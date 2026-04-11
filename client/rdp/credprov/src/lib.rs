//! NetBird RDP Credential Provider for Windows.
//!
//! This DLL is a Windows Credential Provider that enables passwordless RDP access
//! to machines running the NetBird agent. It is loaded by Windows' LogonUI.exe
//! via COM when the login screen is displayed.
//!
//! ## How it works
//!
//! 1. The DLL is registered as a Credential Provider in the Windows registry
//! 2. When an RDP session begins, LogonUI loads the DLL
//! 3. The DLL queries the local NetBird agent via named pipe for pending sessions
//! 4. If a pending session exists for the connecting peer, the DLL:
//!    - Shows a "NetBird Login" credential tile
//!    - Performs S4U logon to create a Windows token without a password
//!    - Returns the token to LogonUI for session creation

mod credential;
mod guid;
mod named_pipe_client;
mod provider;
mod s4u;

use guid::CLSID_NETBIRD_CREDENTIAL_PROVIDER;
use provider::NetBirdCredentialProvider;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Com::*;

/// DLL reference count for COM lifecycle management.
static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

/// DLL module handle.
static mut DLL_MODULE: HMODULE = HMODULE(std::ptr::null_mut());

/// COM class factory for creating NetBirdCredentialProvider instances.
#[implement(IClassFactory)]
struct NetBirdClassFactory;

impl IClassFactory_Impl for NetBirdClassFactory_Impl {
    fn CreateInstance(
        &self,
        _punkouter: Option<&IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut std::ffi::c_void,
    ) -> Result<()> {
        unsafe {
            if !ppvobject.is_null() {
                *ppvobject = std::ptr::null_mut();
            }
        }

        if _punkouter.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        let provider = NetBirdCredentialProvider::new();
        let unknown: IUnknown = provider.into();

        unsafe {
            unknown.query(riid, ppvobject).ok()
        }
    }

    fn LockServer(&self, flock: BOOL) -> Result<()> {
        if flock.as_bool() {
            DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
        } else {
            DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// DLL entry point.
#[no_mangle]
extern "system" fn DllMain(hinstance: HMODULE, reason: u32, _reserved: *mut std::ffi::c_void) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DLL_MODULE = hinstance;
        }
    }

    TRUE
}

/// COM entry point: returns a class factory for the requested CLSID.
#[no_mangle]
extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut std::ffi::c_void,
) -> HRESULT {
    unsafe {
        if ppv.is_null() {
            return E_POINTER;
        }
        *ppv = std::ptr::null_mut();

        if *rclsid != CLSID_NETBIRD_CREDENTIAL_PROVIDER {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        let factory = NetBirdClassFactory;
        let unknown: IUnknown = factory.into();

        match unknown.query(riid, ppv) {
            Ok(()) => S_OK,
            Err(e) => e.code(),
        }
    }
}

/// COM entry point: indicates whether the DLL can be unloaded.
#[no_mangle]
extern "system" fn DllCanUnloadNow() -> HRESULT {
    if DLL_REF_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

/// Self-registration: called by regsvr32 to register the credential provider.
#[no_mangle]
extern "system" fn DllRegisterServer() -> HRESULT {
    match register_credential_provider(true) {
        Ok(()) => S_OK,
        Err(_) => E_FAIL,
    }
}

/// Self-unregistration: called by regsvr32 /u to unregister the credential provider.
#[no_mangle]
extern "system" fn DllUnregisterServer() -> HRESULT {
    match register_credential_provider(false) {
        Ok(()) => S_OK,
        Err(_) => E_FAIL,
    }
}

fn register_credential_provider(register: bool) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::Registry::*;

    let clsid_str = format!("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data1,
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data2,
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data3,
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[0],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[1],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[2],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[3],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[4],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[5],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[6],
        CLSID_NETBIRD_CREDENTIAL_PROVIDER.data4[7],
    );

    if register {
        // Register under Credential Providers
        let cp_key_path = format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{}",
            clsid_str
        );

        let cp_key_wide: Vec<u16> = cp_key_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();

        unsafe {
            let result = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(cp_key_wide.as_ptr()),
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hkey,
                None,
            );
            if result.is_err() {
                return Err("Failed to create credential provider registry key".into());
            }

            let value: Vec<u16> = "NetBird RDP Credential Provider"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let _ = RegSetValueExW(
                hkey,
                PCWSTR::null(),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    value.as_ptr() as *const u8,
                    value.len() * 2,
                )),
            );
            let _ = RegCloseKey(hkey);
        }

        // Register CLSID in CLSID hive
        let clsid_key_path = format!(r"CLSID\{}", clsid_str);
        let clsid_key_wide: Vec<u16> = clsid_key_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = RegCreateKeyExW(
                HKEY_CLASSES_ROOT,
                PCWSTR(clsid_key_wide.as_ptr()),
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hkey,
                None,
            );
            if result.is_err() {
                return Err("Failed to create CLSID registry key".into());
            }
            let _ = RegCloseKey(hkey);

            // InprocServer32 subkey
            let inproc_path = format!(r"CLSID\{}\InprocServer32", clsid_str);
            let inproc_wide: Vec<u16> = inproc_path.encode_utf16().chain(std::iter::once(0)).collect();

            let result = RegCreateKeyExW(
                HKEY_CLASSES_ROOT,
                PCWSTR(inproc_wide.as_ptr()),
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hkey,
                None,
            );
            if result.is_err() {
                return Err("Failed to create InprocServer32 registry key".into());
            }

            // Set DLL path
            let mut dll_path = [0u16; 260];
            let len = windows::Win32::System::LibraryLoader::GetModuleFileNameW(
                DLL_MODULE,
                &mut dll_path,
            );
            if len > 0 {
                let _ = RegSetValueExW(
                    hkey,
                    PCWSTR::null(),
                    0,
                    REG_SZ,
                    Some(std::slice::from_raw_parts(
                        dll_path.as_ptr() as *const u8,
                        (len as usize + 1) * 2,
                    )),
                );
            }

            // Set threading model
            let threading: Vec<u16> = "Apartment"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let threading_name: Vec<u16> = "ThreadingModel"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let _ = RegSetValueExW(
                hkey,
                PCWSTR(threading_name.as_ptr()),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    threading.as_ptr() as *const u8,
                    threading.len() * 2,
                )),
            );

            let _ = RegCloseKey(hkey);
        }
    } else {
        // Unregister
        let cp_key_path = format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{}",
            clsid_str
        );
        let cp_key_wide: Vec<u16> = cp_key_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let _ = RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(cp_key_wide.as_ptr()));
        }

        let inproc_path = format!(r"CLSID\{}\InprocServer32", clsid_str);
        let inproc_wide: Vec<u16> = inproc_path.encode_utf16().chain(std::iter::once(0)).collect();
        let clsid_key_path = format!(r"CLSID\{}", clsid_str);
        let clsid_wide: Vec<u16> = clsid_key_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let _ = RegDeleteKeyW(HKEY_CLASSES_ROOT, PCWSTR(inproc_wide.as_ptr()));
            let _ = RegDeleteKeyW(HKEY_CLASSES_ROOT, PCWSTR(clsid_wide.as_ptr()));
        }
    }

    Ok(())
}
