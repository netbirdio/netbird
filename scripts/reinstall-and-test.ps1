<#
.SYNOPSIS
    Reinstall and test NetBird Machine Tunnel after reset.

.DESCRIPTION
    This script automates the reinstall and test cycle:
    1. Runs reset-netbird-machine.ps1 for clean state
    2. Installs the new binary
    3. Starts the service
    4. Verifies basic functionality

.PARAMETER BinaryPath
    Path to the netbird-machine.exe binary to install.

.PARAMETER ConfigPath
    Optional path to a config file to use.

.PARAMETER SkipReset
    Skip the reset step (useful if already reset).

.PARAMETER WaitForTunnel
    Wait for tunnel to establish (timeout in seconds).

.EXAMPLE
    .\reinstall-and-test.ps1 -BinaryPath .\netbird-machine.exe
    Full reset, install, and test cycle.

.EXAMPLE
    .\reinstall-and-test.ps1 -BinaryPath .\netbird-machine.exe -SkipReset
    Install without reset (assumes clean state).

.NOTES
    Requires: Administrator privileges
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BinaryPath,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipReset,

    [Parameter(Mandatory = $false)]
    [int]$WaitForTunnel = 60
)

$ErrorActionPreference = 'Stop'

# Configuration
$ServiceName = "NetBirdMachine"
$InterfaceName = "wg-nb-machine"
$InstallPath = "$env:ProgramFiles\NetBird Machine"
$ConfigDir = "$env:ProgramData\NetBird"

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

function Write-Failure {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Wait-TunnelUp {
    param([int]$TimeoutSeconds)

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -eq 'Up') {
            return $true
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
        Write-Host "." -NoNewline
    }
    Write-Host ""
    return $false
}

#endregion

#region Main Script

# Check administrator
if (-not (Test-Administrator)) {
    throw "This script must be run as Administrator"
}

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║          NetBird Machine Tunnel Reinstall & Test                  ║
╚═══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# ============================================
# Step 1: Reset (Optional)
# ============================================
if (-not $SkipReset) {
    Write-Step "Step 1: Resetting previous installation"

    $resetScript = Join-Path $PSScriptRoot "reset-netbird-machine.ps1"
    if (Test-Path $resetScript) {
        & $resetScript -Force -KeepConfig:$false
    } else {
        Write-Host "Reset script not found, performing manual cleanup..."
        # Inline minimal cleanup
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName 2>&1 | Out-Null
    }

    # Verify cleanup
    $verifyScript = Join-Path $PSScriptRoot "verify-nrpt-cleanup.ps1"
    if (Test-Path $verifyScript) {
        & $verifyScript
    }

    Write-Success "Reset complete"
} else {
    Write-Host "Skipping reset (--SkipReset)" -ForegroundColor Yellow
}

# ============================================
# Step 2: Install Binary
# ============================================
Write-Step "Step 2: Installing binary"

# Create install directory
if (-not (Test-Path $InstallPath)) {
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
}

# Copy binary
$targetBinary = Join-Path $InstallPath "netbird-machine.exe"
Copy-Item -Path $BinaryPath -Destination $targetBinary -Force
Write-Success "Binary copied to: $targetBinary"

# Create config directory
if (-not (Test-Path $ConfigDir)) {
    New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
}

# Copy config if provided
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    $targetConfig = Join-Path $ConfigDir "config.yaml"
    Copy-Item -Path $ConfigPath -Destination $targetConfig -Force
    Write-Success "Config copied to: $targetConfig"
}

# ============================================
# Step 3: Install Service
# ============================================
Write-Step "Step 3: Installing service"

if ($PSCmdlet.ShouldProcess($targetBinary, "Install service")) {
    $result = & $targetBinary install 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Service installed"
    } else {
        Write-Failure "Service install failed: $result"
        throw "Service installation failed"
    }
}

# ============================================
# Step 4: Start Service
# ============================================
Write-Step "Step 4: Starting service"

if ($PSCmdlet.ShouldProcess($ServiceName, "Start service")) {
    Start-Service $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 2

    $service = Get-Service $ServiceName
    if ($service.Status -eq 'Running') {
        Write-Success "Service started"
    } else {
        Write-Failure "Service status: $($service.Status)"
        throw "Service failed to start"
    }
}

# ============================================
# Step 5: Wait for Tunnel
# ============================================
Write-Step "Step 5: Waiting for tunnel ($WaitForTunnel seconds max)"

Write-Host "Waiting for interface $InterfaceName" -NoNewline
if (Wait-TunnelUp -TimeoutSeconds $WaitForTunnel) {
    Write-Success "Tunnel is UP"

    # Get interface details
    $adapter = Get-NetAdapter -Name $InterfaceName
    $ipConfig = Get-NetIPAddress -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue

    Write-Host "`nInterface Details:" -ForegroundColor White
    Write-Host "  Name:   $($adapter.Name)"
    Write-Host "  Status: $($adapter.Status)"
    Write-Host "  MAC:    $($adapter.MacAddress)"
    if ($ipConfig) {
        Write-Host "  IP:     $($ipConfig.IPAddress)"
    }
} else {
    Write-Failure "Tunnel did not come up within $WaitForTunnel seconds"
    Write-Host "`nCheck logs:" -ForegroundColor Yellow
    Write-Host "  Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
    throw "Tunnel establishment timeout"
}

# ============================================
# Step 6: Basic Connectivity Test
# ============================================
Write-Step "Step 6: Basic connectivity test"

# Check if we can ping the NetBird network
$testTargets = @(
    @{ Name = "NetBird Gateway"; IP = "100.64.0.1" }
)

$allPassed = $true
foreach ($target in $testTargets) {
    Write-Host "  Testing $($target.Name) ($($target.IP))... " -NoNewline
    $ping = Test-Connection -ComputerName $target.IP -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        Write-Success "OK"
    } else {
        Write-Host "[--] Not reachable (may be expected)" -ForegroundColor Gray
    }
}

# ============================================
# Summary
# ============================================
Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                    Installation Complete                          ║
╚═══════════════════════════════════════════════════════════════════╝

Service:   $ServiceName (Running)
Interface: $InterfaceName (Up)
Binary:    $targetBinary

Next steps:
1. Check service logs: Get-EventLog -LogName Application -Source $ServiceName -Newest 20
2. Test DC connectivity (if configured)
3. Test domain operations

"@ -ForegroundColor Green

#endregion
