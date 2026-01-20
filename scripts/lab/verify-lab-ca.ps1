#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies Lab CA setup is complete and working
.DESCRIPTION
    Checks all components required for NetBird Machine Certificate enrollment:
    - AD CS Service
    - NetBirdMachine Template
    - Auto-Enrollment GPO
    - RPC Port Range
    - DNS Service
    - DCOM Permissions
.EXAMPLE
    .\verify-lab-ca.ps1
#>

$ErrorActionPreference = "Continue"

Write-Host "=== NetBird Lab CA Verification ===" -ForegroundColor Cyan
Write-Host "Running on: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Time: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

$checks = @{
    Passed = 0
    Failed = 0
    Warnings = 0
}

function Write-Check {
    param(
        [string]$Name,
        [string]$Status,  # Pass, Fail, Warn
        [string]$Message
    )

    switch ($Status) {
        "Pass" {
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
            Write-Host "$Name" -ForegroundColor White
            if ($Message) { Write-Host "         $Message" -ForegroundColor Gray }
            $script:checks.Passed++
        }
        "Fail" {
            Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
            Write-Host "$Name" -ForegroundColor White
            if ($Message) { Write-Host "         $Message" -ForegroundColor Yellow }
            $script:checks.Failed++
        }
        "Warn" {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
            Write-Host "$Name" -ForegroundColor White
            if ($Message) { Write-Host "         $Message" -ForegroundColor Gray }
            $script:checks.Warnings++
        }
    }
}

# =============================================================================
# Check 1: CA Service
# =============================================================================
Write-Host "[1/7] Checking CA Service..." -ForegroundColor Yellow

$svc = Get-Service CertSvc -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Check "CertSvc" "Fail" "AD CS not installed"
} elseif ($svc.Status -eq "Running") {
    Write-Check "CertSvc" "Pass" "Service is running"
} else {
    Write-Check "CertSvc" "Fail" "Service status: $($svc.Status)"
}

# =============================================================================
# Check 2: CA Configuration
# =============================================================================
Write-Host "[2/7] Checking CA Configuration..." -ForegroundColor Yellow

$caInfo = certutil -getreg CA\CommonName 2>&1
if ($caInfo -match "CommonName.*REG_SZ.*=\s*(.+)") {
    $caName = $Matches[1].Trim()
    Write-Check "CA Name" "Pass" $caName
} else {
    Write-Check "CA Name" "Fail" "Could not determine CA name"
}

# =============================================================================
# Check 3: NetBirdMachine Template
# =============================================================================
Write-Host "[3/7] Checking NetBirdMachine Template..." -ForegroundColor Yellow

$templates = certutil -CATemplates 2>&1
if ($templates -match "NetBirdMachine") {
    Write-Check "Template Published" "Pass" "NetBirdMachine is available on CA"

    # Check template properties in AD
    $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $templatePath = "CN=NetBirdMachine,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configContext"
    $template = [ADSI]"LDAP://$templatePath"

    if ($template.Name) {
        # Check EKU
        $eku = $template."pKIExtendedKeyUsage"
        if ($eku -contains "1.3.6.1.5.5.7.3.2") {
            Write-Check "Template EKU" "Pass" "Client Authentication present"
        } else {
            Write-Check "Template EKU" "Fail" "Missing Client Authentication EKU"
        }

        # Check Name Flag (DNS in SAN)
        $nameFlag = $template."msPKI-Certificate-Name-Flag"
        if ($nameFlag -band 0x8000000) {
            Write-Check "Template SAN" "Pass" "DNS name in SAN enabled"
        } else {
            Write-Check "Template SAN" "Warn" "DNS name in SAN may not be configured"
        }

        # Check Private Key Flag
        $pkFlag = $template."msPKI-Private-Key-Flag"
        if ($pkFlag -eq 0) {
            Write-Check "Private Key" "Pass" "Not exportable"
        } else {
            Write-Check "Private Key" "Warn" "May be exportable (flag: $pkFlag)"
        }

        # Check Enrollment Flag
        $enrollFlag = $template."msPKI-Enrollment-Flag"
        if ($enrollFlag -band 32) {
            Write-Check "Auto-Enrollment" "Pass" "Enabled on template"
        } else {
            Write-Check "Auto-Enrollment" "Warn" "May not be enabled on template"
        }
    }
} else {
    Write-Check "Template Published" "Fail" "NetBirdMachine not found in CA templates"
}

# =============================================================================
# Check 4: Auto-Enrollment GPO
# =============================================================================
Write-Host "[4/7] Checking Auto-Enrollment GPO..." -ForegroundColor Yellow

try {
    $gpo = Get-GPO -Name "NetBird-AutoEnrollment" -ErrorAction Stop
    Write-Check "GPO Exists" "Pass" "ID: $($gpo.Id)"

    # Check if linked
    $links = Get-GPLink -Name "NetBird-AutoEnrollment" -ErrorAction SilentlyContinue
    if ($links) {
        Write-Check "GPO Linked" "Pass" "Linked to: $($links.Target)"
    } else {
        Write-Check "GPO Linked" "Warn" "GPO exists but may not be linked"
    }

    # Check registry values
    $regValues = Get-GPRegistryValue -Name "NetBird-AutoEnrollment" -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ErrorAction SilentlyContinue
    $aePolicy = $regValues | Where-Object { $_.ValueName -eq "AEPolicy" }
    if ($aePolicy -and $aePolicy.Value -eq 7) {
        Write-Check "AEPolicy" "Pass" "Value = 7 (Enroll + Renew + Update)"
    } else {
        Write-Check "AEPolicy" "Warn" "AEPolicy may not be configured correctly"
    }
} catch {
    Write-Check "GPO Exists" "Fail" "GPO 'NetBird-AutoEnrollment' not found"
}

# =============================================================================
# Check 5: RPC Port Range
# =============================================================================
Write-Host "[5/7] Checking RPC Port Range..." -ForegroundColor Yellow

$rpcConfig = netsh int ipv4 show dynamicport tcp
if ($rpcConfig -match "Start Port\s*:\s*(\d+)") {
    $startPort = [int]$Matches[1]
    if ($startPort -eq 5000) {
        Write-Check "RPC Range" "Pass" "Start port: 5000 (restricted for firewall)"
    } elseif ($startPort -eq 49152) {
        Write-Check "RPC Range" "Warn" "Default range (49152-65535) - consider restricting to 5000-5100"
    } else {
        Write-Check "RPC Range" "Pass" "Start port: $startPort"
    }
}

# =============================================================================
# Check 6: DNS Service
# =============================================================================
Write-Host "[6/7] Checking DNS Service..." -ForegroundColor Yellow

$dns = Get-Service DNS -ErrorAction SilentlyContinue
if ($null -eq $dns) {
    Write-Check "DNS Service" "Warn" "DNS service not found (may not be a DC)"
} elseif ($dns.Status -eq "Running") {
    Write-Check "DNS Service" "Pass" "DNS is running"
} else {
    Write-Check "DNS Service" "Fail" "DNS status: $($dns.Status)"
}

# =============================================================================
# Check 7: DCOM Permissions
# =============================================================================
Write-Host "[7/7] Checking DCOM Permissions..." -ForegroundColor Yellow

try {
    $group = [ADSI]"WinNT://./Certificate Service DCOM Access,group"
    $members = @($group.Invoke("Members")) | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }

    if ($members -contains "Domain Computers") {
        Write-Check "DCOM Access" "Pass" "Domain Computers in DCOM group"
    } else {
        Write-Check "DCOM Access" "Warn" "Domain Computers may not be in DCOM group"
    }
} catch {
    Write-Check "DCOM Access" "Warn" "Could not check DCOM group: $_"
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "  Passed:   $($checks.Passed)" -ForegroundColor Green
Write-Host "  Warnings: $($checks.Warnings)" -ForegroundColor Yellow
Write-Host "  Failed:   $($checks.Failed)" -ForegroundColor Red
Write-Host ""

if ($checks.Failed -eq 0) {
    if ($checks.Warnings -eq 0) {
        Write-Host "All checks passed! CA is ready for use." -ForegroundColor Green
    } else {
        Write-Host "CA is functional with warnings. Review warnings above." -ForegroundColor Yellow
    }
    exit 0
} else {
    Write-Host "CA setup incomplete. Fix failed checks before proceeding." -ForegroundColor Red
    exit 1
}
