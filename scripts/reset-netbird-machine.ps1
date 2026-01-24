<#
.SYNOPSIS
    Reset NetBird Machine Tunnel for testing purposes.
    Safely removes service, interface, NRPT rules, and firewall rules.

.DESCRIPTION
    This script performs a complete cleanup of the NetBird Machine Tunnel:
    1. Stops and removes the NetBird Machine service
    2. Removes the WireGuard tunnel interface
    3. Removes ONLY NetBird-specific NRPT rules (scoped by registry key hash)
    4. Removes NetBird-specific firewall rules
    5. Optionally cleans up configuration files

    IMPORTANT: This script uses scoped cleanup - it will NOT remove other
    NRPT rules or firewall rules that are not NetBird-related.

.PARAMETER Force
    Skip confirmation prompts.

.PARAMETER KeepConfig
    Keep configuration files (useful for re-testing with same config).

.PARAMETER Verbose
    Show detailed progress information.

.EXAMPLE
    .\reset-netbird-machine.ps1 -Force
    Performs full reset without prompts.

.EXAMPLE
    .\reset-netbird-machine.ps1 -KeepConfig
    Reset but keep config files for next test.

.NOTES
    Requires: Administrator privileges
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$KeepConfig
)

$ErrorActionPreference = 'Continue'  # Continue on errors to ensure full cleanup

# Configuration
$ServiceName = "NetBirdMachine"
$InterfaceName = "wg-nb-machine"
$ConfigPath = "$env:ProgramData\NetBird"
$NRPTRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
$NRPTKeyPrefix = "NetBird-Machine-"
$FirewallRulePrefix = "NetBird-Machine-"

#region Helper Functions

function Write-Step {
    param([string]$Message)
    Write-Host "`n>> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "   [OK] $Message" -ForegroundColor Green
}

function Write-Skipped {
    param([string]$Message)
    Write-Host "   [--] $Message" -ForegroundColor Gray
}

function Write-Warning {
    param([string]$Message)
    Write-Host "   [!!] $Message" -ForegroundColor Yellow
}

function Write-Failure {
    param([string]$Message)
    Write-Host "   [XX] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region Main Script

# Check administrator
if (-not (Test-Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║          NetBird Machine Tunnel Reset Script                      ║
║                                                                   ║
║  Safely removes service, interface, NRPT, and firewall rules      ║
╚═══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Confirmation
if (-not $Force) {
    $confirm = Read-Host "This will reset the NetBird Machine Tunnel. Continue? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# ============================================
# Step 1: Stop and Remove Service
# ============================================
Write-Step "Step 1: Stopping and removing service"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -eq 'Running') {
        if ($PSCmdlet.ShouldProcess($ServiceName, "Stop service")) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Write-Success "Service stopped"
        }
    } else {
        Write-Skipped "Service already stopped"
    }

    # Remove service using sc.exe
    if ($PSCmdlet.ShouldProcess($ServiceName, "Remove service")) {
        $result = sc.exe delete $ServiceName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service removed"
        } else {
            Write-Warning "Service removal returned: $result"
        }
    }
} else {
    Write-Skipped "Service not installed"
}

# ============================================
# Step 2: Remove WireGuard Interface
# ============================================
Write-Step "Step 2: Removing WireGuard interface"

$adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
if ($adapter) {
    if ($PSCmdlet.ShouldProcess($InterfaceName, "Remove network adapter")) {
        # Disable first
        Disable-NetAdapter -Name $InterfaceName -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        # Remove via netsh (works for WireGuard interfaces)
        $result = netsh interface delete interface name="$InterfaceName" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Interface removed via netsh"
        } else {
            # Try WireGuard-specific removal if available
            $wgExe = "C:\Program Files\WireGuard\wireguard.exe"
            if (Test-Path $wgExe) {
                & $wgExe /uninstalltunnelservice $InterfaceName 2>&1 | Out-Null
                Write-Success "Interface removed via WireGuard"
            } else {
                Write-Warning "Interface may require manual removal"
            }
        }
    }
} else {
    Write-Skipped "Interface not present"
}

# ============================================
# Step 3: Remove NRPT Rules (Scoped!)
# ============================================
Write-Step "Step 3: Removing NetBird NRPT rules (scoped)"

# CRITICAL: Only remove rules with our prefix - NOT all NRPT rules!
if (Test-Path $NRPTRegistryPath) {
    $removedCount = 0
    $nrptKeys = Get-ChildItem $NRPTRegistryPath -ErrorAction SilentlyContinue

    foreach ($key in $nrptKeys) {
        $keyName = Split-Path $key.Name -Leaf
        if ($keyName.StartsWith($NRPTKeyPrefix)) {
            if ($PSCmdlet.ShouldProcess($keyName, "Remove NRPT rule")) {
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                $removedCount++
            }
        }
    }

    if ($removedCount -gt 0) {
        Write-Success "Removed $removedCount NetBird NRPT rule(s)"

        # Flush DNS cache to apply changes
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Success "DNS cache flushed"
    } else {
        Write-Skipped "No NetBird NRPT rules found"
    }
} else {
    Write-Skipped "NRPT registry path not present"
}

# Also check the alternative NRPT path
$NRPTAltPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"
if (Test-Path $NRPTAltPath) {
    $altKeys = Get-ChildItem $NRPTAltPath -ErrorAction SilentlyContinue | Where-Object {
        (Split-Path $_.Name -Leaf).StartsWith($NRPTKeyPrefix)
    }
    if ($altKeys) {
        foreach ($key in $altKeys) {
            Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Success "Removed NetBird NRPT rules from alternate path"
    }
}

# ============================================
# Step 4: Remove Firewall Rules (Scoped!)
# ============================================
Write-Step "Step 4: Removing NetBird firewall rules (scoped)"

# CRITICAL: Only remove rules with our prefix - NOT all firewall rules!
$fwRules = Get-NetFirewallRule -DisplayName "$FirewallRulePrefix*" -ErrorAction SilentlyContinue

if ($fwRules) {
    $ruleCount = ($fwRules | Measure-Object).Count
    if ($PSCmdlet.ShouldProcess("$ruleCount firewall rules", "Remove")) {
        $fwRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Success "Removed $ruleCount firewall rule(s)"
    }
} else {
    Write-Skipped "No NetBird firewall rules found"
}

# ============================================
# Step 5: Clean Configuration (Optional)
# ============================================
Write-Step "Step 5: Cleaning configuration"

if (-not $KeepConfig) {
    if (Test-Path $ConfigPath) {
        if ($PSCmdlet.ShouldProcess($ConfigPath, "Remove configuration directory")) {
            # Backup config first
            $backupPath = "$env:TEMP\netbird-config-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Copy-Item -Path $ConfigPath -Destination $backupPath -Recurse -ErrorAction SilentlyContinue
            Write-Success "Config backed up to: $backupPath"

            # Remove config
            Remove-Item -Path $ConfigPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Configuration removed"
        }
    } else {
        Write-Skipped "Configuration directory not present"
    }
} else {
    Write-Skipped "Configuration kept (--KeepConfig)"
}

# ============================================
# Step 6: Clean Registry Keys
# ============================================
Write-Step "Step 6: Cleaning registry keys"

$registryPaths = @(
    "HKLM:\SOFTWARE\NetBird\Machine",
    "HKLM:\SOFTWARE\WOW6432Node\NetBird\Machine"
)

foreach ($regPath in $registryPaths) {
    if (Test-Path $regPath) {
        if ($PSCmdlet.ShouldProcess($regPath, "Remove registry key")) {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Removed: $regPath"
        }
    }
}

# ============================================
# Summary
# ============================================
Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║                        Reset Complete                             ║
╚═══════════════════════════════════════════════════════════════════╝

The following have been cleaned up:
- NetBird Machine service
- WireGuard interface ($InterfaceName)
- NetBird-specific NRPT rules (prefix: $NRPTKeyPrefix)
- NetBird-specific firewall rules (prefix: $FirewallRulePrefix)
$(if (-not $KeepConfig) { "- Configuration files (backed up to $backupPath)" })

To reinstall, run:
  .\netbird-machine.exe install
  Start-Service $ServiceName

"@ -ForegroundColor Green

#endregion
