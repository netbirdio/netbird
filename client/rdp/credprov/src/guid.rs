use windows::core::GUID;

/// CLSID for the NetBird RDP Credential Provider.
/// Generated UUID: {7B3A8E5F-1C4D-4F8A-B2E6-9D0F3A7C5E1B}
pub const CLSID_NETBIRD_CREDENTIAL_PROVIDER: GUID = GUID::from_u128(
    0x7B3A8E5F_1C4D_4F8A_B2E6_9D0F3A7C5E1B,
);

/// Registry path for credential providers.
pub const CREDENTIAL_PROVIDER_REGISTRY_PATH: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";
