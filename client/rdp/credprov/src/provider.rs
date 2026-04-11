//! ICredentialProvider implementation.
//!
//! This is the main COM object that Windows' LogonUI.exe instantiates.
//! It determines whether to show a "NetBird Login" credential tile based on
//! whether the NetBird agent has a pending RDP session for the connecting peer.

use crate::credential::NetBirdCredential;
use crate::guid::CLSID_NETBIRD_CREDENTIAL_PROVIDER;
use crate::named_pipe_client::NamedPipeClient;
use std::sync::Mutex;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Credentials::*;
use windows::Win32::System::RemoteDesktop::*;

/// The NetBird Credential Provider, loaded by LogonUI.exe via COM.
#[implement(ICredentialProvider)]
pub struct NetBirdCredentialProvider {
    /// The credential tile (if a pending session was found).
    credential: Mutex<Option<ICredentialProviderCredential>>,
    /// Whether this provider is active for the current usage scenario.
    active: Mutex<bool>,
}

impl NetBirdCredentialProvider {
    pub fn new() -> Self {
        Self {
            credential: Mutex::new(None),
            active: Mutex::new(false),
        }
    }
}

impl ICredentialProvider_Impl for NetBirdCredentialProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> Result<()> {
        let mut active = self.active.lock().unwrap();

        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                // We activate for RDP logon and unlock scenarios
                *active = true;
                log::info!("NetBird CP activated for usage scenario {:?}", cpus.0);
                Ok(())
            }
            _ => {
                // Don't activate for credui or other scenarios
                *active = false;
                Err(E_NOTIMPL.into())
            }
        }
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn Advise(
        &self,
        _pcpe: Option<&ICredentialProviderEvents>,
        _upadvisecontext: usize,
    ) -> Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> Result<u32> {
        // We have one field: a large text label showing "NetBird: Logging in as <user>"
        Ok(1)
    }

    fn GetFieldDescriptorAt(
        &self,
        _dwindex: u32,
        _ppcpfd: *mut *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    ) -> Result<()> {
        if _dwindex != 0 {
            return Err(E_INVALIDARG.into());
        }

        let label = "NetBird Login";
        let wide: Vec<u16> = label.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let desc = windows::Win32::System::Com::CoTaskMemAlloc(
                std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>(),
            ) as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;

            if desc.is_null() {
                return Err(E_OUTOFMEMORY.into());
            }

            let label_mem =
                windows::Win32::System::Com::CoTaskMemAlloc(wide.len() * 2) as *mut u16;
            if label_mem.is_null() {
                windows::Win32::System::Com::CoTaskMemFree(Some(desc as *const _));
                return Err(E_OUTOFMEMORY.into());
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), label_mem, wide.len());

            (*desc).dwFieldID = 0;
            (*desc).cpft = CPFT_LARGE_TEXT;
            (*desc).pszLabel = PWSTR(label_mem);
            (*desc).guidFieldType = GUID::zeroed();

            *_ppcpfd = desc;
        }

        Ok(())
    }

    fn GetCredentialCount(
        &self,
        _pdwcount: *mut u32,
        _pdwdefault: *mut u32,
        _pbautologinwithdefault: *mut BOOL,
    ) -> Result<()> {
        let active = self.active.lock().unwrap();
        if !*active {
            unsafe {
                *_pdwcount = 0;
                *_pdwdefault = u32::MAX;
                *_pbautologinwithdefault = FALSE;
            }
            return Ok(());
        }

        // Try to get the client IP of the current RDP session
        let remote_ip = match get_rdp_client_ip() {
            Some(ip) => ip,
            None => {
                log::debug!("NetBird CP: could not determine RDP client IP");
                unsafe {
                    *_pdwcount = 0;
                    *_pdwdefault = u32::MAX;
                    *_pbautologinwithdefault = FALSE;
                }
                return Ok(());
            }
        };

        // Query the NetBird agent for a pending session
        match NamedPipeClient::query_pending(&remote_ip) {
            Ok(response) if response.found => {
                log::info!(
                    "NetBird CP: found pending session for {} -> {}",
                    remote_ip,
                    response.os_user
                );

                let cred = NetBirdCredential::new(remote_ip, response);
                let icred: ICredentialProviderCredential = cred.into();

                let mut credential = self.credential.lock().unwrap();
                *credential = Some(icred);

                unsafe {
                    *_pdwcount = 1;
                    *_pdwdefault = 0;
                    *_pbautologinwithdefault = TRUE; // auto-logon
                }
            }
            Ok(_) => {
                log::debug!("NetBird CP: no pending session for {}", remote_ip);
                unsafe {
                    *_pdwcount = 0;
                    *_pdwdefault = u32::MAX;
                    *_pbautologinwithdefault = FALSE;
                }
            }
            Err(e) => {
                log::debug!("NetBird CP: pipe query failed: {}", e);
                unsafe {
                    *_pdwcount = 0;
                    *_pdwdefault = u32::MAX;
                    *_pbautologinwithdefault = FALSE;
                }
            }
        }

        Ok(())
    }

    fn GetCredentialAt(
        &self,
        _dwindex: u32,
        _ppcpc: *mut Option<ICredentialProviderCredential>,
    ) -> Result<()> {
        if _dwindex != 0 {
            return Err(E_INVALIDARG.into());
        }

        let credential = self.credential.lock().unwrap();
        match &*credential {
            Some(cred) => {
                unsafe {
                    *_ppcpc = Some(cred.clone());
                }
                Ok(())
            }
            None => Err(E_UNEXPECTED.into()),
        }
    }
}

/// Get the IP address of the remote RDP client for the current session.
fn get_rdp_client_ip() -> Option<String> {
    unsafe {
        // Get the current session ID
        let process_id = windows::Win32::System::Threading::GetCurrentProcessId();
        let mut session_id = 0u32;

        if !windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(process_id, &mut session_id)
            .as_bool()
        {
            log::debug!("ProcessIdToSessionId failed");
            return None;
        }

        // Query the client address
        let mut buffer: *mut WTS_CLIENT_ADDRESS = std::ptr::null_mut();
        let mut bytes_returned = 0u32;

        let result = WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTS_INFO_CLASS(14), // WTSClientAddress
            &mut buffer as *mut _ as *mut *mut u16,
            &mut bytes_returned,
        );

        if !result.as_bool() || buffer.is_null() {
            log::debug!("WTSQuerySessionInformation(WTSClientAddress) failed");
            return None;
        }

        let client_addr = &*buffer;
        let ip = match client_addr.AddressFamily as u32 {
            // AF_INET
            2 => {
                let addr = &client_addr.Address;
                Some(format!("{}.{}.{}.{}", addr[2], addr[3], addr[4], addr[5]))
            }
            // AF_INET6
            23 => {
                // IPv6 - extract from Address bytes
                let addr = &client_addr.Address;
                Some(format!(
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9],
                    addr[10], addr[11], addr[12], addr[13], addr[14], addr[15], addr[16], addr[17]
                ))
            }
            _ => None,
        };

        WTSFreeMemory(buffer as *mut std::ffi::c_void);

        ip
    }
}
