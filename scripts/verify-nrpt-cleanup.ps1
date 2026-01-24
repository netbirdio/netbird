<#
.SYNOPSIS
    Verify NRPT cleanup after NetBird Machine Tunnel reset.

.DESCRIPTION
    This script checks all NRPT-related registry paths and PowerShell cmdlets
    to verify that NetBird-specific NRPT rules have been properly removed
    while other NRPT rules remain intact.

    Checks:
    1. Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig
    2. Registry: HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig
    3. PowerShell: Get-DnsClientNrptRule

.PARAMETER ShowAll
    Show all NRPT rules, not just NetBird-related ones.

.EXAMPLE
    .\verify-nrpt-cleanup.ps1
    Checks for any remaining NetBird NRPT rules.

.EXAMPLE
    .\verify-nrpt-cleanup.ps1 -ShowAll
    Shows all NRPT rules in the system.

.NOTES
    Requires: Administrator privileges (for some registry paths)
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ShowAll
)

$NRPTKeyPrefix = "NetBird-Machine-"

Write-Host @"

╔═══════════════════════════════════════════════════════════════════╗
║              NRPT Cleanup Verification                            ║
╚═══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

$issuesFound = $false

# ============================================
# Check 1: Policy Registry Path
# ============================================
Write-Host ">> Checking: Policy Registry Path" -ForegroundColor Yellow
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"

if (Test-Path $policyPath) {
    $policyKeys = Get-ChildItem $policyPath -ErrorAction SilentlyContinue

    $netbirdRules = $policyKeys | Where-Object {
        (Split-Path $_.Name -Leaf).StartsWith($NRPTKeyPrefix)
    }

    $otherRules = $policyKeys | Where-Object {
        -not (Split-Path $_.Name -Leaf).StartsWith($NRPTKeyPrefix)
    }

    if ($netbirdRules) {
        Write-Host "   [FAIL] Found $($netbirdRules.Count) NetBird NRPT rule(s):" -ForegroundColor Red
        foreach ($rule in $netbirdRules) {
            Write-Host "          - $(Split-Path $rule.Name -Leaf)" -ForegroundColor Red
        }
        $issuesFound = $true
    } else {
        Write-Host "   [OK] No NetBird NRPT rules found" -ForegroundColor Green
    }

    if ($ShowAll -and $otherRules) {
        Write-Host "   [INFO] Other NRPT rules present: $($otherRules.Count)" -ForegroundColor Cyan
        foreach ($rule in $otherRules) {
            Write-Host "          - $(Split-Path $rule.Name -Leaf)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "   [OK] Policy path not present (clean)" -ForegroundColor Green
}

# ============================================
# Check 2: Dnscache Registry Path
# ============================================
Write-Host "`n>> Checking: Dnscache Registry Path" -ForegroundColor Yellow
$dnscachePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"

if (Test-Path $dnscachePath) {
    $dnscacheKeys = Get-ChildItem $dnscachePath -ErrorAction SilentlyContinue

    $netbirdRules = $dnscacheKeys | Where-Object {
        (Split-Path $_.Name -Leaf).StartsWith($NRPTKeyPrefix)
    }

    $otherRules = $dnscacheKeys | Where-Object {
        -not (Split-Path $_.Name -Leaf).StartsWith($NRPTKeyPrefix)
    }

    if ($netbirdRules) {
        Write-Host "   [FAIL] Found $($netbirdRules.Count) NetBird NRPT rule(s):" -ForegroundColor Red
        foreach ($rule in $netbirdRules) {
            Write-Host "          - $(Split-Path $rule.Name -Leaf)" -ForegroundColor Red
        }
        $issuesFound = $true
    } else {
        Write-Host "   [OK] No NetBird NRPT rules found" -ForegroundColor Green
    }

    if ($ShowAll -and $otherRules) {
        Write-Host "   [INFO] Other NRPT rules present: $($otherRules.Count)" -ForegroundColor Cyan
        foreach ($rule in $otherRules) {
            Write-Host "          - $(Split-Path $rule.Name -Leaf)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "   [OK] Dnscache path not present (clean)" -ForegroundColor Green
}

# ============================================
# Check 3: PowerShell Get-DnsClientNrptRule
# ============================================
Write-Host "`n>> Checking: PowerShell NRPT Rules" -ForegroundColor Yellow

try {
    $psRules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue

    if ($psRules) {
        $netbirdRules = $psRules | Where-Object {
            $_.Name -like "$NRPTKeyPrefix*" -or
            $_.Comment -like "*NetBird*" -or
            $_.Namespace -like "*netbird*"
        }

        $otherRules = $psRules | Where-Object {
            $_.Name -notlike "$NRPTKeyPrefix*" -and
            $_.Comment -notlike "*NetBird*" -and
            $_.Namespace -notlike "*netbird*"
        }

        if ($netbirdRules) {
            Write-Host "   [FAIL] Found $($netbirdRules.Count) NetBird NRPT rule(s) via PowerShell:" -ForegroundColor Red
            foreach ($rule in $netbirdRules) {
                Write-Host "          - $($rule.Name): $($rule.Namespace)" -ForegroundColor Red
            }
            $issuesFound = $true
        } else {
            Write-Host "   [OK] No NetBird NRPT rules found via PowerShell" -ForegroundColor Green
        }

        if ($ShowAll -and $otherRules) {
            Write-Host "   [INFO] Other NRPT rules via PowerShell: $($otherRules.Count)" -ForegroundColor Cyan
            foreach ($rule in $otherRules) {
                Write-Host "          - $($rule.Name): $($rule.Namespace)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "   [OK] No NRPT rules found via PowerShell" -ForegroundColor Green
    }
} catch {
    Write-Host "   [WARN] Could not query PowerShell NRPT rules: $_" -ForegroundColor Yellow
}

# ============================================
# Summary
# ============================================
Write-Host ""
if ($issuesFound) {
    Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  VERIFICATION FAILED: NetBird NRPT rules still present            ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "Run reset-netbird-machine.ps1 -Force to clean up." -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  VERIFICATION PASSED: No NetBird NRPT rules found                 ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    exit 0
}
