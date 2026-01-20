#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Test certificate auto-enrollment on a domain-joined client
.DESCRIPTION
    Tests Machine Certificate enrollment by:
    1. Checking domain membership
    2. Verifying GPO settings
    3. Running enrollment in SYSTEM context (required for machine certs!)
    4. Validating the issued certificate

    IMPORTANT: Machine certificate enrollment MUST run as SYSTEM (LocalSystem),
    not as a logged-in user. This script uses a Scheduled Task to achieve this.
.PARAMETER TemplateName
    Certificate template name (default: NetBirdMachine)
.PARAMETER CAConfig
    CA configuration string (default: auto-detect)
.PARAMETER Force
    Force new enrollment even if certificate exists
.EXAMPLE
    .\test-client-enrollment.ps1
.EXAMPLE
    .\test-client-enrollment.ps1 -Force -Verbose
#>

[CmdletBinding()]
param(
    [string]$TemplateName = "NetBirdMachine",
    [string]$CAConfig = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Certificate Enrollment Test ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Template: $TemplateName" -ForegroundColor Gray
Write-Host "Time: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

# =============================================================================
# Pre-Flight Checks
# =============================================================================
Write-Host "[1/5] Pre-flight checks..." -ForegroundColor Yellow

# Check domain membership
$cs = Get-WmiObject Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    Write-Host "  ERROR: Computer is not domain-joined!" -ForegroundColor Red
    Write-Host "  Run: Add-Computer -DomainName <domain> -Credential (Get-Credential)" -ForegroundColor Yellow
    exit 1
}
Write-Host "  Domain: $($cs.Domain)" -ForegroundColor Green

# Check if certificate already exists
$existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -match "CN=$env:COMPUTERNAME" -and
    $_.NotAfter -gt (Get-Date)
}

if ($existingCert -and -not $Force) {
    Write-Host "  Machine certificate already exists:" -ForegroundColor Green
    Write-Host "    Subject:    $($existingCert.Subject)" -ForegroundColor Gray
    Write-Host "    Thumbprint: $($existingCert.Thumbprint)" -ForegroundColor Gray
    Write-Host "    Expires:    $($existingCert.NotAfter)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Use -Force to request a new certificate anyway." -ForegroundColor Yellow
    exit 0
}

# =============================================================================
# GPO Update
# =============================================================================
Write-Host "[2/5] Updating Group Policy..." -ForegroundColor Yellow
$gpResult = gpupdate /force /target:computer 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  GPO update successful." -ForegroundColor Green
} else {
    Write-Host "  GPO update may have issues: $gpResult" -ForegroundColor Yellow
}

# Check AEPolicy registry value
$aePath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment"
$aePolicy = Get-ItemProperty -Path $aePath -Name "AEPolicy" -ErrorAction SilentlyContinue
if ($aePolicy -and $aePolicy.AEPolicy -eq 7) {
    Write-Host "  AEPolicy = 7 (Auto-enrollment enabled)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: AEPolicy not set to 7. GPO may not be applied." -ForegroundColor Yellow
}

# =============================================================================
# SYSTEM Context Enrollment (via Scheduled Task)
# =============================================================================
Write-Host "[3/5] Running enrollment as SYSTEM..." -ForegroundColor Yellow
Write-Host "  (Machine certs require SYSTEM context, not user context)" -ForegroundColor Gray

$taskName = "NetBird-CertEnroll-Test"
$resultFile = "$env:TEMP\cert-enroll-result.txt"
$certFile = "$env:TEMP\machine-cert.cer"

# Cleanup previous files
Remove-Item $resultFile -ErrorAction SilentlyContinue
Remove-Item $certFile -ErrorAction SilentlyContinue

# Script to run as SYSTEM
$enrollScript = @"
`$ErrorActionPreference = 'Continue'
`$log = @()
`$log += "=== SYSTEM Enrollment Log ==="
`$log += "Time: `$(Get-Date)"
`$log += "Identity: `$(whoami)"
`$log += ""

# Check Kerberos tickets
`$log += "Kerberos tickets:"
`$klist = klist -li 0x3e7 2>&1
`$log += `$klist | Out-String

# Trigger certificate pulse
`$log += "Running certutil -pulse..."
`$pulse = certutil -pulse 2>&1
`$log += `$pulse | Out-String

# Wait for enrollment
Start-Sleep -Seconds 5

# Check for certificate
`$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    `$_.Subject -match "CN=`$env:COMPUTERNAME"
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (`$cert) {
    `$log += "SUCCESS: Certificate found!"
    `$log += "Subject: `$(`$cert.Subject)"
    `$log += "Thumbprint: `$(`$cert.Thumbprint)"
    `$log += "Issuer: `$(`$cert.Issuer)"
    `$log += "NotAfter: `$(`$cert.NotAfter)"
    `$log += "HasPrivateKey: `$(`$cert.HasPrivateKey)"

    # Check SAN
    `$san = `$cert.DnsNameList | ForEach-Object { `$_.Unicode }
    `$log += "SAN DNS Names: `$(`$san -join ', ')"

    # Check EKU
    `$eku = `$cert.EnhancedKeyUsageList | ForEach-Object { `$_.FriendlyName }
    `$log += "EKU: `$(`$eku -join ', ')"

    # Export public cert for verification
    `$certBytes = `$cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes("$certFile", `$certBytes)
} else {
    `$log += "FAILED: No certificate found after enrollment"

    # Try to get more info
    `$log += ""
    `$log += "Attempting manual enrollment..."
    `$inf = @"
[NewRequest]
Subject = "CN=`$env:COMPUTERNAME.`$((Get-WmiObject Win32_ComputerSystem).Domain)"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
[RequestAttributes]
CertificateTemplate = $TemplateName
"@
    `$inf | Out-File "`$env:TEMP\machine.inf" -Encoding ASCII
    `$req = certreq -new -machine "`$env:TEMP\machine.inf" "`$env:TEMP\machine.csr" 2>&1
    `$log += `$req | Out-String
}

`$log | Out-File "$resultFile" -Encoding UTF8
"@

# Save script to temp file
$scriptFile = "$env:TEMP\enroll-as-system.ps1"
$enrollScript | Out-File $scriptFile -Encoding UTF8

# Create and run scheduled task as SYSTEM
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptFile`""
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$task = New-ScheduledTask -Action $action -Principal $principal

# Remove existing task if present
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Register and run
Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

# Wait for completion
Write-Host "  Waiting for enrollment (max 30 seconds)..." -ForegroundColor Gray
$timeout = 30
$elapsed = 0
while ($elapsed -lt $timeout) {
    Start-Sleep -Seconds 2
    $elapsed += 2

    $taskInfo = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($taskInfo.State -eq "Ready") {
        break
    }
}

# Cleanup task
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# =============================================================================
# Results
# =============================================================================
Write-Host "[4/5] Checking results..." -ForegroundColor Yellow

if (Test-Path $resultFile) {
    $results = Get-Content $resultFile -Raw
    Write-Verbose $results

    if ($results -match "SUCCESS: Certificate found") {
        Write-Host "  Enrollment SUCCESSFUL!" -ForegroundColor Green
    } else {
        Write-Host "  Enrollment may have failed. Details:" -ForegroundColor Yellow
        Write-Host $results -ForegroundColor Gray
    }
} else {
    Write-Host "  ERROR: Result file not created. Task may have failed." -ForegroundColor Red
}

# =============================================================================
# Final Verification
# =============================================================================
Write-Host "[5/5] Final verification..." -ForegroundColor Yellow

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -match "CN=$env:COMPUTERNAME"
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if ($cert) {
    Write-Host ""
    Write-Host "=== Machine Certificate ===" -ForegroundColor Green
    Write-Host "Subject:     $($cert.Subject)"
    Write-Host "Issuer:      $($cert.Issuer)"
    Write-Host "Thumbprint:  $($cert.Thumbprint)"
    Write-Host "Valid From:  $($cert.NotBefore)"
    Write-Host "Valid Until: $($cert.NotAfter)"
    Write-Host "PrivateKey:  $($cert.HasPrivateKey)"

    # SAN
    $sanList = $cert.DnsNameList | ForEach-Object { $_.Unicode }
    Write-Host "SAN DNS:     $($sanList -join ', ')"

    # EKU
    $ekuList = $cert.EnhancedKeyUsageList | ForEach-Object { "$($_.FriendlyName) ($($_.ObjectId))" }
    Write-Host "EKU:         $($ekuList -join ', ')"

    # Exportable check
    try {
        $exportable = $cert.PrivateKey.CspKeyContainerInfo.Exportable
        Write-Host "Exportable:  $exportable"
    } catch {
        Write-Host "Exportable:  (could not determine)"
    }

    Write-Host ""
    Write-Host "Certificate enrollment successful!" -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "=== FAILED ===" -ForegroundColor Red
    Write-Host "No machine certificate found after enrollment."
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Check Event Log: Applications and Services > Microsoft > Windows > CertificateServicesClient-AutoEnrollment"
    Write-Host "2. Verify template permissions: certtmpl.msc > NetBirdMachine > Security"
    Write-Host "3. Test CA connectivity: certutil -ping -config <CA>"
    Write-Host "4. Check DCOM permissions on CA server"
    exit 1
}
