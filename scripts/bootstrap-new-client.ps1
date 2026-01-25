<#
.SYNOPSIS
    Bootstrap script for new NetBird Machine Tunnel clients.
    Performs Phase 1 (Setup-Key) -> Domain Join -> Certificate Enrollment -> Phase 2 (mTLS).

.DESCRIPTION
    This script automates the full bootstrap process for a new Windows client:
    1. Pre-Tunnel NTP sync (pool.ntp.org)
    2. Install/Start NetBird Machine Service with Setup-Key
    3. Wait for tunnel establishment
    4. Verify DC connectivity via tunnel
    5. NTP sync with DC (Kerberos requirement)
    6. Domain Join
    7. Certificate Enrollment via AD CS
    8. Update NetBird config for mTLS
    9. Restart service for Phase 2

.PARAMETER SetupKey
    The one-time Setup-Key from NetBird Management (UUID format).

.PARAMETER DomainName
    The FQDN of the Active Directory domain (e.g., "corp.local").

.PARAMETER DCAddress
    The IP address of the Domain Controller (e.g., "192.168.100.20").

.PARAMETER OUPath
    Optional. The OU path for the computer object.
    Format: "OU=Computers,DC=corp,DC=local"

.PARAMETER CertTemplateName
    The AD CS certificate template name for machine certificates.
    Default: "NetBirdMachineTunnel"

.PARAMETER NoRestart
    Skip automatic restart after domain join.

.PARAMETER WhatIf
    Show what would be done without making changes.

.EXAMPLE
    .\bootstrap-new-client.ps1 -SetupKey "a1b2c3d4-e5f6-7890-abcd-ef1234567890" -DomainName "corp.local" -DCAddress "192.168.100.20"

.NOTES
    Requires: Administrator privileges, PowerShell 5.1+
    Author: NetBird Machine Tunnel Fork
    Version: 2.0.0

    SECURITY CONSIDERATIONS:

    1. Script Verification (before running):
       - Verify SHA256 checksum: Get-FileHash .\bootstrap-new-client.ps1 -Algorithm SHA256
       - Compare with published checksum in CHECKSUMS.txt or release notes

    2. Authenticode Signing (for production deployments):
       - Sign with code signing certificate: Set-AuthenticodeSignature -FilePath .\bootstrap-new-client.ps1 -Certificate $cert
       - Verify signature: Get-AuthenticodeSignature .\bootstrap-new-client.ps1

    3. Setup-Key Handling:
       - Setup-Keys are one-time use with 24h TTL
       - ALWAYS revoke Setup-Key in Dashboard after bootstrap
       - Setup-Key is redacted in all logs (only last 4 chars shown)
       - Setup-Key is removed from local config after mTLS upgrade
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$SetupKey,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    [string]$DCAddress,

    [Parameter(Mandatory = $false)]
    [string]$OUPath = "",

    [Parameter(Mandatory = $false)]
    [string]$CertTemplateName = "NetBirdMachineTunnel",

    [Parameter(Mandatory = $false)]
    [switch]$NoRestart
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Configuration paths
$NetBirdConfigPath = "$env:ProgramData\NetBird\config.yaml"
$NetBirdServiceName = "NetBirdMachine"
$TunnelInterface = "wg-nb-machine"

#region Helper Functions

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Failure {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DCConnectivity {
    param([string]$DC, [int]$Port)

    try {
        $result = Test-NetConnection -ComputerName $DC -Port $Port -WarningAction SilentlyContinue -ErrorAction Stop
        return $result.TcpTestSucceeded
    } catch {
        return $false
    }
}

function Wait-TunnelUp {
    param(
        [int]$TimeoutSeconds = 60,
        [int]$CheckIntervalSeconds = 2
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        # Check if tunnel interface exists
        $interface = Get-NetAdapter -Name $TunnelInterface -ErrorAction SilentlyContinue
        if ($interface -and $interface.Status -eq 'Up') {
            return $true
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
        $elapsed += $CheckIntervalSeconds
        Write-Host "." -NoNewline
    }
    Write-Host ""
    return $false
}

function Get-TimeDifferenceSeconds {
    param([string]$NtpServer)

    try {
        $output = w32tm /stripchart /computer:$NtpServer /samples:1 /dataonly 2>&1
        if ($output -match '([+-]?\d+\.\d+)s') {
            return [math]::Abs([double]$Matches[1])
        }
    } catch {
        Write-Warning "Could not measure time difference: $_"
    }
    return $null
}

#endregion

#region Main Script

# Check prerequisites
if (-not (Test-Administrator)) {
    throw "This script must be run as Administrator"
}

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║          NetBird Machine Tunnel Bootstrap Script                  ║
║                                                                   ║
║  Phase 1: Setup-Key → Domain Join → Cert → Phase 2: mTLS         ║
╚═══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Redact Setup-Key for logging (show only last 4 chars)
$SetupKeyRedacted = "****-****-****-****-" + $SetupKey.Substring($SetupKey.Length - 4)

Write-Host "Configuration:" -ForegroundColor White
Write-Host "  Domain:    $DomainName"
Write-Host "  DC:        $DCAddress"
Write-Host "  Setup-Key: $SetupKeyRedacted"
if ($OUPath) { Write-Host "  OU Path:   $OUPath" }
Write-Host "  Template:  $CertTemplateName"
Write-Host ""

# ============================================
# Step 1: Pre-Tunnel NTP Sync
# ============================================
Write-Step "Step 1: Pre-Tunnel NTP Sync (Public NTP)"

if ($PSCmdlet.ShouldProcess("W32Time", "Configure public NTP")) {
    try {
        # Use public NTP before tunnel is up
        w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:no /update | Out-Null
        Restart-Service W32Time -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        w32tm /resync /nowait | Out-Null
        Write-Success "Public NTP sync initiated"
    } catch {
        Write-Warning "Public NTP sync failed: $_ (continuing...)"
    }
}

# ============================================
# Step 2: Start NetBird Service with Setup-Key
# ============================================
Write-Step "Step 2: Starting NetBird Machine Service (Phase 1: Setup-Key)"

if ($PSCmdlet.ShouldProcess($NetBirdServiceName, "Install and start with Setup-Key")) {
    # Check if service exists
    $service = Get-Service -Name $NetBirdServiceName -ErrorAction SilentlyContinue

    if (-not $service) {
        throw "NetBird Machine Service is not installed. Run the installer first."
    }

    # Update config with setup key
    if (Test-Path $NetBirdConfigPath) {
        $config = Get-Content $NetBirdConfigPath -Raw
        if ($config -notmatch 'setup_key:') {
            Add-Content $NetBirdConfigPath "`nsetup_key: $SetupKey"
        } else {
            $config = $config -replace 'setup_key:.*', "setup_key: $SetupKey"
            Set-Content $NetBirdConfigPath $config
        }
        Write-Success "Config updated with Setup-Key"
    } else {
        throw "NetBird config not found at $NetBirdConfigPath"
    }

    # Start/Restart service
    if ($service.Status -eq 'Running') {
        Restart-Service $NetBirdServiceName
    } else {
        Start-Service $NetBirdServiceName
    }

    Write-Success "Service started"

    # Wait for tunnel
    Write-Host "Waiting for tunnel to establish" -NoNewline
    if (-not (Wait-TunnelUp -TimeoutSeconds 60)) {
        throw "Tunnel did not come up within 60 seconds. Check NetBird logs."
    }
    Write-Success "Tunnel is UP"
}

# ============================================
# Step 3: Verify DC Connectivity via Tunnel
# ============================================
Write-Step "Step 3: Verifying DC Connectivity via Tunnel"

$requiredPorts = @(
    @{Name = "LDAP"; Port = 389},
    @{Name = "Kerberos"; Port = 88},
    @{Name = "DNS"; Port = 53}
)

$allReachable = $true
foreach ($port in $requiredPorts) {
    Write-Host "  Testing $($port.Name) (port $($port.Port))... " -NoNewline
    if (Test-DCConnectivity -DC $DCAddress -Port $port.Port) {
        Write-Success "OK"
    } else {
        Write-Failure "FAILED"
        $allReachable = $false
    }
}

if (-not $allReachable) {
    throw "DC connectivity check failed. Ensure the tunnel routes DC traffic correctly."
}
Write-Success "All required DC ports reachable via tunnel"

# ============================================
# Step 4: NTP Sync with DC (Kerberos Requirement)
# ============================================
Write-Step "Step 4: NTP Sync with Domain Controller"

if ($PSCmdlet.ShouldProcess("W32Time", "Configure DC NTP")) {
    # Configure DC as NTP source
    w32tm /config /manualpeerlist:"$DCAddress" /syncfromflags:manual /reliable:no /update | Out-Null
    Restart-Service W32Time -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    w32tm /resync /nowait | Out-Null

    # Check time difference
    $timeDiff = Get-TimeDifferenceSeconds -NtpServer $DCAddress
    if ($null -ne $timeDiff) {
        if ($timeDiff -gt 300) {
            Write-Warning "Time difference is ${timeDiff}s (>5min). Kerberos may fail!"
            Write-Host "  Waiting for sync..." -NoNewline
            Start-Sleep -Seconds 10
            w32tm /resync /nowait | Out-Null
            Start-Sleep -Seconds 5
            $timeDiff = Get-TimeDifferenceSeconds -NtpServer $DCAddress
        }

        if ($null -ne $timeDiff -and $timeDiff -le 300) {
            Write-Success "Time synchronized (diff: ${timeDiff}s)"
        } else {
            Write-Warning "Could not verify time sync. Proceeding with caution."
        }
    } else {
        Write-Warning "Could not measure time difference. Proceeding..."
    }
}

# ============================================
# Step 5: Domain Join
# ============================================
Write-Step "Step 5: Domain Join"

# Check if already joined
$computerSystem = Get-WmiObject Win32_ComputerSystem
if ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName) {
    Write-Success "Computer is already joined to $DomainName"
} else {
    if ($PSCmdlet.ShouldProcess($DomainName, "Join domain")) {
        Write-Host "Joining domain: $DomainName"
        Write-Host "(You will be prompted for domain admin credentials)"

        $joinParams = @{
            DomainName = $DomainName
            Credential = (Get-Credential -Message "Enter domain admin credentials for $DomainName")
            Force = $true
            Restart = $false
        }

        if ($OUPath) {
            $joinParams.OUPath = $OUPath
        }

        try {
            Add-Computer @joinParams
            Write-Success "Domain join successful!"
        } catch {
            throw "Domain join failed: $_"
        }
    }
}

# ============================================
# Step 6: Certificate Enrollment
# ============================================
Write-Step "Step 6: Machine Certificate Enrollment"

if ($PSCmdlet.ShouldProcess("AD CS", "Request machine certificate")) {
    Write-Host "Requesting machine certificate using template: $CertTemplateName"

    # Use certreq for enrollment
    $infContent = @"
[NewRequest]
Subject = "CN=$env:COMPUTERNAME.$DomainName"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate = $CertTemplateName
"@

    $infPath = "$env:TEMP\certreq.inf"
    $reqPath = "$env:TEMP\certreq.req"
    $cerPath = "$env:TEMP\certreq.cer"

    try {
        Set-Content -Path $infPath -Value $infContent

        # Generate request
        $result = certreq -new -machine $infPath $reqPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -new failed: $result"
        }

        # Submit to CA (assumes auto-enrollment CA discovery)
        $result = certreq -submit -machine $reqPath $cerPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -submit failed: $result"
        }

        # Accept certificate
        $result = certreq -accept -machine $cerPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "certreq -accept failed: $result"
        }

        Write-Success "Certificate enrolled successfully"

        # Get thumbprint
        $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Subject -match $env:COMPUTERNAME } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        if ($cert) {
            Write-Host "  Certificate Thumbprint: $($cert.Thumbprint)"
            Write-Host "  Valid Until: $($cert.NotAfter)"

            # Save thumbprint for config update
            $certThumbprint = $cert.Thumbprint
        }
    } finally {
        # Cleanup temp files
        Remove-Item $infPath, $reqPath, $cerPath -ErrorAction SilentlyContinue
    }
}

# ============================================
# Step 7: Update NetBird Config for mTLS (Smart Selection v3.6)
# ============================================
Write-Step "Step 7: Updating NetBird Config for mTLS (Phase 2 - Smart Selection)"

if ($PSCmdlet.ShouldProcess($NetBirdConfigPath, "Enable mTLS with Smart Selection")) {
    # v3.6: Use Smart Cert Selection - no thumbprint needed!
    # Smart Selection automatically finds the right cert based on:
    # - Template name match
    # - SAN must match hostname.domain
    # - Most recent valid cert
    $configUpdate = @"

# Machine Certificate Authentication (Phase 2 - Smart Selection v3.6)
# No thumbprint needed - NetBird automatically selects the right certificate!
machine_cert_enabled: true
machine_cert_template_name: $CertTemplateName
machine_cert_san_must_match: true
"@
    Add-Content $NetBirdConfigPath $configUpdate

    # Remove setup key from config (CRITICAL: security requirement!)
    $config = Get-Content $NetBirdConfigPath -Raw
    $config = $config -replace 'setup_key:.*\n', ''
    Set-Content $NetBirdConfigPath $config

    Write-Success "Config updated for mTLS (Smart Selection)"
    Write-Host "  Template: $CertTemplateName" -ForegroundColor Gray
    Write-Host "  SAN Match: hostname.$DomainName" -ForegroundColor Gray

    if ($certThumbprint) {
        Write-Host "  Found Cert: $($certThumbprint.Substring(0,16))..." -ForegroundColor Gray
    }
}

# ============================================
# Step 8: Restart or Prompt
# ============================================
Write-Step "Step 8: Completing Bootstrap"

# CRITICAL SECURITY WARNING
Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║  ⚠️  SECURITY ACTION REQUIRED                                      ║
║                                                                   ║
║  REVOKE the Setup-Key in NetBird Dashboard immediately!           ║
║                                                                   ║
║  Setup-Key used: $SetupKeyRedacted
║                                                                   ║
║  The Setup-Key has been removed from local config, but it         ║
║  must also be revoked on the server to prevent reuse.            ║
║                                                                   ║
║  Dashboard → Setup Keys → Find & Revoke                           ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Yellow

if ($NoRestart) {
    Write-Host @"

Bootstrap complete! Manual steps required:
1. REVOKE the Setup-Key in NetBird Dashboard (see above)
2. Restart the computer to complete domain join
3. After restart, the NetBird service will use mTLS (Phase 2)

"@ -ForegroundColor Cyan
} else {
    Write-Host @"

Bootstrap complete!

The computer will restart in 30 seconds to complete:
- Domain join finalization
- NetBird service restart with mTLS (Phase 2)

REMEMBER: REVOKE the Setup-Key in NetBird Dashboard!

Press Ctrl+C to cancel restart.

"@ -ForegroundColor Green

    if ($PSCmdlet.ShouldProcess("Computer", "Restart")) {
        Start-Sleep -Seconds 30
        Restart-Computer -Force
    }
}

#endregion
