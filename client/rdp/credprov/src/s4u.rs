//! S4U (Service for User) authentication for Windows.
//!
//! This module ports the S4U logon logic from the Go implementation at:
//! `client/ssh/server/executor_windows.go:generateS4UUserToken()`
//!
//! It creates Windows logon tokens without requiring a password, using the LSA
//! (Local Security Authority) S4U mechanism. This is the same approach used by
//! OpenSSH for Windows for public key authentication.

use std::ptr;
use windows::core::{PCSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, LUID, NTSTATUS, PSID};
use windows::Win32::Security::Authentication::Identity::{
    LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser, LsaLookupAuthenticationPackage,
    LsaRegisterLogonProcess, KERB_S4U_LOGON, MSV1_0_S4U_LOGON, MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS,
    SECURITY_LOGON_TYPE,
};
use windows::Win32::Security::{
    QUOTA_LIMITS, TOKEN_SOURCE,
};

/// Status code for successful LSA operations.
const STATUS_SUCCESS: i32 = 0;

/// Network logon type (used for S4U).
const LOGON32_LOGON_NETWORK: SECURITY_LOGON_TYPE = SECURITY_LOGON_TYPE(3);

/// Kerberos S4U logon message type.
const KERB_S4U_LOGON_TYPE: u32 = 12;

/// MSV1_0 S4U logon message type.
const MSV1_0_S4U_LOGON_TYPE: u32 = 12;

/// Authentication package name for Kerberos.
const KERBEROS_PACKAGE: &str = "Kerberos";

/// Authentication package name for MSV1_0 (local users).
const MSV1_0_PACKAGE: &str = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";

/// Result of a successful S4U logon.
pub struct S4UToken {
    pub handle: HANDLE,
}

impl Drop for S4UToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }
}

/// Errors from S4U logon operations.
#[derive(Debug)]
pub enum S4UError {
    LsaRegister(NTSTATUS),
    LookupPackage(NTSTATUS),
    LogonUser(NTSTATUS, i32),
    AllocateLuid,
    InvalidUsername(String),
    Utf16Conversion(String),
}

impl std::fmt::Display for S4UError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S4UError::LsaRegister(s) => write!(f, "LsaRegisterLogonProcess: 0x{:x}", s.0),
            S4UError::LookupPackage(s) => write!(f, "LsaLookupAuthenticationPackage: 0x{:x}", s.0),
            S4UError::LogonUser(s, sub) => {
                write!(f, "LsaLogonUser S4U: NTSTATUS=0x{:x}, SubStatus=0x{:x}", s.0, sub)
            }
            S4UError::AllocateLuid => write!(f, "AllocateLocallyUniqueId failed"),
            S4UError::InvalidUsername(u) => write!(f, "invalid username: {}", u),
            S4UError::Utf16Conversion(s) => write!(f, "UTF-16 conversion: {}", s),
        }
    }
}

impl std::error::Error for S4UError {}

/// Generate a Windows logon token using S4U authentication.
///
/// This creates a token for the specified user without requiring a password.
/// The calling process must have SeTcbPrivilege (typically SYSTEM).
///
/// # Arguments
/// * `username` - The Windows username (without domain prefix)
/// * `domain` - The domain name ("." for local users)
///
/// # Returns
/// An `S4UToken` containing the Windows logon token handle.
pub fn generate_s4u_token(username: &str, domain: &str) -> Result<S4UToken, S4UError> {
    if username.is_empty() {
        return Err(S4UError::InvalidUsername("empty username".to_string()));
    }

    let is_local = is_local_user(domain);

    // Initialize LSA connection
    let lsa_handle = initialize_lsa_connection()?;

    // Lookup authentication package
    let auth_package_id = lookup_auth_package(lsa_handle, is_local)?;

    // Perform S4U logon
    let result = perform_s4u_logon(lsa_handle, auth_package_id, username, domain, is_local);

    // Cleanup LSA connection
    unsafe {
        let _ = LsaDeregisterLogonProcess(lsa_handle);
    }

    result
}

fn is_local_user(domain: &str) -> bool {
    domain.is_empty() || domain == "."
}

fn initialize_lsa_connection() -> Result<HANDLE, S4UError> {
    let process_name = "NetBird\0";
    let mut lsa_string = windows::Win32::Security::Authentication::Identity::LSA_STRING {
        Length: (process_name.len() - 1) as u16,
        MaximumLength: process_name.len() as u16,
        Buffer: windows::core::PSTR(process_name.as_ptr() as *mut u8),
    };

    let mut lsa_handle = HANDLE::default();
    let mut mode = 0u32;

    let status = unsafe {
        LsaRegisterLogonProcess(&mut lsa_string, &mut lsa_handle, &mut mode)
    };

    if status.0 != STATUS_SUCCESS {
        return Err(S4UError::LsaRegister(status));
    }

    Ok(lsa_handle)
}

fn lookup_auth_package(lsa_handle: HANDLE, is_local: bool) -> Result<u32, S4UError> {
    let package_name = if is_local { MSV1_0_PACKAGE } else { KERBEROS_PACKAGE };
    let package_with_null = format!("{}\0", package_name);

    let mut lsa_string = windows::Win32::Security::Authentication::Identity::LSA_STRING {
        Length: (package_with_null.len() - 1) as u16,
        MaximumLength: package_with_null.len() as u16,
        Buffer: windows::core::PSTR(package_with_null.as_ptr() as *mut u8),
    };

    let mut auth_package_id = 0u32;
    let status = unsafe {
        LsaLookupAuthenticationPackage(lsa_handle, &mut lsa_string, &mut auth_package_id)
    };

    if status.0 != STATUS_SUCCESS {
        return Err(S4UError::LookupPackage(status));
    }

    Ok(auth_package_id)
}

fn perform_s4u_logon(
    lsa_handle: HANDLE,
    auth_package_id: u32,
    username: &str,
    domain: &str,
    is_local: bool,
) -> Result<S4UToken, S4UError> {
    // Prepare token source
    let mut source_name = [0u8; 8];
    let name_bytes = b"netbird";
    source_name[..name_bytes.len()].copy_from_slice(name_bytes);

    let mut source_id = LUID::default();
    let alloc_ok = unsafe {
        windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime(
            &mut std::mem::zeroed(),
        );
        // Use a simpler approach - just use the current time as a unique ID
        source_id.LowPart = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        source_id.HighPart = std::process::id() as i32;
        true
    };

    if !alloc_ok {
        return Err(S4UError::AllocateLuid);
    }

    let token_source = TOKEN_SOURCE {
        SourceName: source_name,
        SourceIdentifier: source_id,
    };

    let origin_name_str = "netbird\0";
    let mut origin_name = windows::Win32::Security::Authentication::Identity::LSA_STRING {
        Length: (origin_name_str.len() - 1) as u16,
        MaximumLength: origin_name_str.len() as u16,
        Buffer: windows::core::PSTR(origin_name_str.as_ptr() as *mut u8),
    };

    // Build the logon info structure
    let (logon_info_ptr, logon_info_size) = if is_local {
        build_msv1_0_s4u_logon(username)?
    } else {
        build_kerb_s4u_logon(username, domain)?
    };

    let mut profile: *mut std::ffi::c_void = ptr::null_mut();
    let mut profile_size = 0u32;
    let mut logon_id = LUID::default();
    let mut token = HANDLE::default();
    let mut quotas = QUOTA_LIMITS::default();
    let mut sub_status: i32 = 0;

    let status = unsafe {
        LsaLogonUser(
            lsa_handle,
            &mut origin_name,
            LOGON32_LOGON_NETWORK,
            auth_package_id,
            logon_info_ptr as *const std::ffi::c_void,
            logon_info_size as u32,
            None,  // local groups
            &token_source,
            &mut profile,
            &mut profile_size,
            &mut logon_id,
            &mut token,
            &mut quotas,
            &mut sub_status,
        )
    };

    // Free profile buffer if allocated
    if !profile.is_null() {
        unsafe {
            let _ = LsaFreeReturnBuffer(profile);
        }
    }

    // Free the logon info buffer
    unsafe {
        let layout = std::alloc::Layout::from_size_align_unchecked(logon_info_size, 8);
        std::alloc::dealloc(logon_info_ptr as *mut u8, layout);
    }

    if status.0 != STATUS_SUCCESS {
        return Err(S4UError::LogonUser(status, sub_status));
    }

    Ok(S4UToken { handle: token })
}

/// Build MSV1_0_S4U_LOGON structure for local users.
fn build_msv1_0_s4u_logon(username: &str) -> Result<(*mut u8, usize), S4UError> {
    let username_utf16: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let domain_utf16: Vec<u16> = ".".encode_utf16().chain(std::iter::once(0)).collect();

    let username_byte_size = username_utf16.len() * 2;
    let domain_byte_size = domain_utf16.len() * 2;

    // MSV1_0_S4U_LOGON structure:
    // MessageType: u32 (4 bytes)
    // Flags: u32 (4 bytes)
    // UserPrincipalName: UNICODE_STRING (8 bytes on 32-bit, 16 bytes on 64-bit)
    // DomainName: UNICODE_STRING
    let struct_size = std::mem::size_of::<MSV1_0_S4U_LOGON_HEADER>();
    let total_size = struct_size + username_byte_size + domain_byte_size;

    let layout = std::alloc::Layout::from_size_align(total_size, 8).unwrap();
    let buffer = unsafe { std::alloc::alloc_zeroed(layout) };

    if buffer.is_null() {
        return Err(S4UError::Utf16Conversion("allocation failed".to_string()));
    }

    // For the POC, we'll set up the raw bytes manually since the windows-rs
    // MSV1_0_S4U_LOGON structure layout may differ.
    // This is a simplified version - in production, use proper FFI bindings.

    unsafe {
        // MessageType = MSV1_0_S4U_LOGON_TYPE (12)
        *(buffer as *mut u32) = MSV1_0_S4U_LOGON_TYPE;
        // Flags = 0
        *((buffer as *mut u32).add(1)) = 0;

        // Copy username UTF-16 after the structure
        let username_offset = struct_size;
        let username_dest = buffer.add(username_offset);
        ptr::copy_nonoverlapping(
            username_utf16.as_ptr() as *const u8,
            username_dest,
            username_byte_size,
        );

        // Copy domain UTF-16 after username
        let domain_offset = username_offset + username_byte_size;
        let domain_dest = buffer.add(domain_offset);
        ptr::copy_nonoverlapping(
            domain_utf16.as_ptr() as *const u8,
            domain_dest,
            domain_byte_size,
        );

        // Set UNICODE_STRING for UserPrincipalName (offset 8 on 64-bit)
        // Length, MaximumLength, Buffer pointer
        let upn_ptr = buffer.add(8) as *mut u16;
        *upn_ptr = ((username_utf16.len() - 1) * 2) as u16; // Length (without null)
        *(upn_ptr.add(1)) = (username_utf16.len() * 2) as u16; // MaximumLength
        *((buffer.add(8 + 4)) as *mut *const u8) = username_dest; // Buffer

        // Set UNICODE_STRING for DomainName
        let dn_offset = 8 + std::mem::size_of::<UnicodeStringRaw>();
        let dn_ptr = buffer.add(dn_offset) as *mut u16;
        *dn_ptr = ((domain_utf16.len() - 1) * 2) as u16;
        *(dn_ptr.add(1)) = (domain_utf16.len() * 2) as u16;
        *((buffer.add(dn_offset + 4)) as *mut *const u8) = domain_dest;
    }

    Ok((buffer, total_size))
}

/// Build KERB_S4U_LOGON structure for domain users.
fn build_kerb_s4u_logon(username: &str, domain: &str) -> Result<(*mut u8, usize), S4UError> {
    // Build UPN: username@domain
    let upn = format!("{}@{}", username, domain);
    let upn_utf16: Vec<u16> = upn.encode_utf16().chain(std::iter::once(0)).collect();
    let upn_byte_size = upn_utf16.len() * 2;

    let struct_size = std::mem::size_of::<KerbS4ULogonHeader>();
    let total_size = struct_size + upn_byte_size;

    let layout = std::alloc::Layout::from_size_align(total_size, 8).unwrap();
    let buffer = unsafe { std::alloc::alloc_zeroed(layout) };

    if buffer.is_null() {
        return Err(S4UError::Utf16Conversion("allocation failed".to_string()));
    }

    unsafe {
        // MessageType = KERB_S4U_LOGON_TYPE (12)
        *(buffer as *mut u32) = KERB_S4U_LOGON_TYPE;
        // Flags = 0
        *((buffer as *mut u32).add(1)) = 0;

        // Copy UPN UTF-16 after the structure
        let upn_offset = struct_size;
        let upn_dest = buffer.add(upn_offset);
        ptr::copy_nonoverlapping(
            upn_utf16.as_ptr() as *const u8,
            upn_dest,
            upn_byte_size,
        );

        // Set UNICODE_STRING for ClientUpn (offset 8)
        let upn_str_ptr = buffer.add(8) as *mut u16;
        *upn_str_ptr = ((upn_utf16.len() - 1) * 2) as u16;
        *(upn_str_ptr.add(1)) = (upn_utf16.len() * 2) as u16;
        *((buffer.add(8 + 4)) as *mut *const u8) = upn_dest;

        // ClientRealm is empty (zeroed)
    }

    Ok((buffer, total_size))
}

/// Raw UNICODE_STRING layout for size calculation.
#[repr(C)]
struct UnicodeStringRaw {
    _length: u16,
    _maximum_length: u16,
    _buffer: *const u16,
}

/// Header size for MSV1_0_S4U_LOGON (MessageType + Flags + 2x UNICODE_STRING).
#[repr(C)]
struct MSV1_0_S4U_LOGON_HEADER {
    _message_type: u32,
    _flags: u32,
    _user_principal_name: UnicodeStringRaw,
    _domain_name: UnicodeStringRaw,
}

/// Header size for KERB_S4U_LOGON (MessageType + Flags + 2x UNICODE_STRING).
#[repr(C)]
struct KerbS4ULogonHeader {
    _message_type: u32,
    _flags: u32,
    _client_upn: UnicodeStringRaw,
    _client_realm: UnicodeStringRaw,
}
