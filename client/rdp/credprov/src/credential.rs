//! ICredentialProviderCredential implementation.
//!
//! Represents a single "NetBird Login" credential tile on the Windows login screen.
//! When selected, it queries the local NetBird agent for pending RDP sessions and
//! performs S4U logon to authenticate the user without a password.

use crate::named_pipe_client::{NamedPipeClient, PipeResponse};
use crate::s4u;
use std::sync::Mutex;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Credentials::*;
use windows::Win32::UI::Shell::*;

/// NetBird credential tile that appears on the Windows login screen.
#[implement(ICredentialProviderCredential)]
pub struct NetBirdCredential {
    /// The pending session information from the NetBird agent.
    session: Mutex<Option<PipeResponse>>,
    /// The remote IP address of the connecting peer.
    remote_ip: Mutex<String>,
}

impl NetBirdCredential {
    pub fn new(remote_ip: String, session: PipeResponse) -> Self {
        Self {
            session: Mutex::new(Some(session)),
            remote_ip: Mutex::new(remote_ip),
        }
    }
}

impl ICredentialProviderCredential_Impl for NetBirdCredential_Impl {
    fn Advise(&self, _pcpce: Option<&ICredentialProviderCredentialEvents>) -> Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        Ok(())
    }

    fn SetSelected(&self, _pbautologon: *mut BOOL) -> Result<()> {
        // Auto-logon when this credential is selected
        unsafe {
            if !_pbautologon.is_null() {
                *_pbautologon = TRUE;
            }
        }
        Ok(())
    }

    fn SetDeselected(&self) -> Result<()> {
        Ok(())
    }

    fn GetFieldState(
        &self,
        _dwfieldid: u32,
        _pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        _pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> Result<()> {
        // We have a single display-only field showing "NetBird Login"
        unsafe {
            if !_pcpfs.is_null() {
                *_pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            }
            if !_pcpfis.is_null() {
                *_pcpfis = CPFIS_NONE;
            }
        }
        Ok(())
    }

    fn GetStringValue(&self, _dwfieldid: u32) -> Result<PWSTR> {
        let session = self.session.lock().unwrap();
        let text = if let Some(ref s) = *session {
            format!("NetBird: Logging in as {}", s.os_user)
        } else {
            "NetBird Login".to_string()
        };

        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let ptr = unsafe {
            let mem = windows::Win32::System::Com::CoTaskMemAlloc(wide.len() * 2) as *mut u16;
            if mem.is_null() {
                return Err(E_OUTOFMEMORY.into());
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), mem, wide.len());
            PWSTR(mem)
        };

        Ok(ptr)
    }

    fn GetBitmapValue(&self, _dwfieldid: u32) -> Result<HBITMAP> {
        Err(E_NOTIMPL.into())
    }

    fn GetCheckboxValue(&self, _dwfieldid: u32, _pbchecked: *mut BOOL, _ppszlabel: *mut PWSTR) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSubmitButtonValue(&self, _dwfieldid: u32, _pdwadjacentto: *mut u32) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetComboBoxValueCount(&self, _dwfieldid: u32, _pcitems: *mut u32, _pdwselecteditem: *mut u32) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(&self, _dwfieldid: u32, _psz: &PCWSTR) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(&self, _dwfieldid: u32, _dwselecteditem: u32) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(&self, _dwfieldid: u32) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSerialization(
        &self,
        _pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        _pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        let session = self.session.lock().unwrap();
        let session_info = match &*session {
            Some(s) => s.clone(),
            None => {
                unsafe {
                    *_pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                }
                return Ok(());
            }
        };

        // Consume the session with the agent
        if let Err(e) = NamedPipeClient::consume_session(&session_info.session_id) {
            log::error!("Failed to consume RDP session: {}", e);
            unsafe {
                *_pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
            }
            return Ok(());
        }

        // Perform S4U logon
        let username = &session_info.os_user;
        let domain = if session_info.domain.is_empty() {
            "."
        } else {
            &session_info.domain
        };

        match s4u::generate_s4u_token(username, domain) {
            Ok(_token) => {
                // In a full implementation, we would serialize the token into
                // CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION format
                // (KerbInteractiveLogon or MsV1_0InteractiveLogon structure).
                //
                // For the POC, we signal success. The actual serialization requires
                // building the proper KERB_INTERACTIVE_LOGON or MSV1_0_INTERACTIVE_LOGON
                // structure with the token handle, which is complex.
                //
                // TODO: Build proper credential serialization from S4U token
                log::info!(
                    "S4U logon successful for {}\\{}, session {}",
                    domain,
                    username,
                    session_info.session_id
                );

                unsafe {
                    *_pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    // Note: In production, pcpcs would be filled with the serialized credentials
                }

                Ok(())
            }
            Err(e) => {
                log::error!("S4U logon failed for {}\\{}: {}", domain, username, e);
                unsafe {
                    *_pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
                }
                Ok(())
            }
        }
    }

    fn ReportResult(
        &self,
        _ntstatus: NTSTATUS,
        _ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        Ok(())
    }
}
