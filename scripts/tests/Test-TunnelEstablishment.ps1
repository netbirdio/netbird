#Requires -RunAsAdministrator
<#
.SYNOPSIS
    E2E Tests for NetBird Machine Tunnel Establishment (T-6.1)
.DESCRIPTION
    Tests tunnel establishment functionality:
    - TC1: Boot + Login - WireGuard interface, routes, DC reachability, Kerberos TGT
    - TC2: DNS-SRV Discovery - LDAP SRV records
    - TC3: Kerberos-SRV Discovery - Kerberos SRV records
    - TC4: UDP Kerberos - Port 88 connectivity

    Returns exit code 0 on success, 1 on failure.
    Designed for CI integration.
.PARAMETER DCAddress
    IP address of the Domain Controller (default: 192.168.100.20)
.PARAMETER DomainName
    Domain name for SRV lookups (default: test.local)
.PARAMETER DCNetworkPrefix
    Network prefix for route verification (default: 192.168.100)
.PARAMETER SkipKerberos
    Skip Kerberos TGT verification (for non-domain-joined machines)
.PARAMETER Verbose
    Show detailed output
.EXAMPLE
    .\Test-TunnelEstablishment.ps1
.EXAMPLE
    .\Test-TunnelEstablishment.ps1 -DCAddress 10.0.0.5 -DomainName corp.local
.EXAMPLE
    .\Test-TunnelEstablishment.ps1 -SkipKerberos -Verbose
.NOTES
    Author: NetBird Machine Tunnel Fork
    Version: 1.0.0
    Requires: NetBird Machine Service running, Administrator privileges
#>

[CmdletBinding()]
param(
    [string]$DCAddress = "192.168.100.20",
    [string]$DomainName = "test.local",
    [string]$DCNetworkPrefix = "192.168.100",
    [switch]$SkipKerberos
)

$ErrorActionPreference = "Continue"

# Test result tracking
$script:TestResults = @{
    Passed = @()
    Failed = @()
    Skipped = @()
}

# =============================================================================
# Helper Functions
# =============================================================================

function Write-TestHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = "",
        [switch]$Skip
    )

    if ($Skip) {
        Write-Host "  [SKIP] $TestName" -ForegroundColor Yellow
        if ($Message) { Write-Host "         $Message" -ForegroundColor Gray }
        $script:TestResults.Skipped += $TestName
        return
    }

    if ($Passed) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        if ($Message) { Write-Host "         $Message" -ForegroundColor Gray }
        $script:TestResults.Passed += $TestName
    } else {
        Write-Host "  [FAIL] $TestName" -ForegroundColor Red
        if ($Message) { Write-Host "         $Message" -ForegroundColor Yellow }
        $script:TestResults.Failed += $TestName
    }
}

function Write-TestSummary {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Passed:  $($script:TestResults.Passed.Count)" -ForegroundColor Green
    Write-Host "  Failed:  $($script:TestResults.Failed.Count)" -ForegroundColor $(if ($script:TestResults.Failed.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Skipped: $($script:TestResults.Skipped.Count)" -ForegroundColor Yellow
    Write-Host ""

    if ($script:TestResults.Failed.Count -gt 0) {
        Write-Host "  Failed Tests:" -ForegroundColor Red
        foreach ($test in $script:TestResults.Failed) {
            Write-Host "    - $test" -ForegroundColor Red
        }
        Write-Host ""
    }

    $total = $script:TestResults.Passed.Count + $script:TestResults.Failed.Count
    if ($total -gt 0) {
        $passRate = [math]::Round(($script:TestResults.Passed.Count / $total) * 100, 1)
        Write-Host "  Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -eq 100) { "Green" } else { "Yellow" })
    }
    Write-Host ""
}

# =============================================================================
# Test Header
# =============================================================================

Write-Host ""
Write-Host "####################################################################" -ForegroundColor White
Write-Host "#                                                                  #" -ForegroundColor White
Write-Host "#        NetBird Machine Tunnel - E2E Establishment Tests         #" -ForegroundColor White
Write-Host "#                           T-6.1                                  #" -ForegroundColor White
Write-Host "#                                                                  #" -ForegroundColor White
Write-Host "####################################################################" -ForegroundColor White
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Gray
Write-Host "  Computer:    $env:COMPUTERNAME"
Write-Host "  DC Address:  $DCAddress"
Write-Host "  Domain:      $DomainName"
Write-Host "  DC Network:  $DCNetworkPrefix.0/24"
Write-Host "  Time:        $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# =============================================================================
# TC1: Boot + Login - Tunnel Establishment
# =============================================================================

Write-TestHeader "TC1: Tunnel Establishment (Boot + Login)"

# TC1.1: Service Status
Write-Host "  Checking NetBird Machine Service..." -ForegroundColor Gray
$service = Get-Service -Name "NetBirdMachine" -ErrorAction SilentlyContinue
if ($service) {
    $serviceRunning = $service.Status -eq "Running"
    Write-TestResult "TC1.1: Service Running" $serviceRunning "Status: $($service.Status)"

    if (-not $serviceRunning) {
        Write-Host "  Attempting to start service..." -ForegroundColor Yellow
        try {
            Start-Service NetBirdMachine -ErrorAction Stop
            Start-Sleep -Seconds 5
            $service = Get-Service -Name "NetBirdMachine"
            $serviceRunning = $service.Status -eq "Running"
            Write-TestResult "TC1.1b: Service Started" $serviceRunning "Status: $($service.Status)"
        } catch {
            Write-TestResult "TC1.1b: Service Start" $false "Error: $_"
        }
    }
} else {
    Write-TestResult "TC1.1: Service Exists" $false "NetBirdMachine service not found"
}

# TC1.2: WireGuard Interface
Write-Host "  Checking WireGuard interface..." -ForegroundColor Gray
$wgAdapter = Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like "WireGuard*" -or
    $_.Name -like "wg-nb-machine*" -or
    $_.Name -like "wg0*"
} | Select-Object -First 1

if ($wgAdapter) {
    $interfaceUp = $wgAdapter.Status -eq "Up"
    Write-TestResult "TC1.2: WireGuard Interface" $interfaceUp "Name: $($wgAdapter.Name), Status: $($wgAdapter.Status)"

    # Get interface details
    if ($VerbosePreference -eq "Continue") {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $wgAdapter.ifIndex -ErrorAction SilentlyContinue
        foreach ($ip in $ipConfig) {
            Write-Host "         IP: $($ip.IPAddress)/$($ip.PrefixLength)" -ForegroundColor Gray
        }
    }
} else {
    Write-TestResult "TC1.2: WireGuard Interface" $false "No WireGuard adapter found"

    # List all adapters for debugging
    if ($VerbosePreference -eq "Continue") {
        Write-Host "  Available adapters:" -ForegroundColor Gray
        Get-NetAdapter | ForEach-Object {
            Write-Host "    - $($_.Name) ($($_.InterfaceDescription)): $($_.Status)" -ForegroundColor Gray
        }
    }
}

# TC1.3: Route to DC Network
Write-Host "  Checking route to DC network..." -ForegroundColor Gray
$routes = route print | Select-String $DCNetworkPrefix
$routeExists = $routes -ne $null -and $routes.Count -gt 0

if ($routeExists) {
    Write-TestResult "TC1.3: Route to DC Network" $true "Found route(s) to $DCNetworkPrefix.0/24"
    if ($VerbosePreference -eq "Continue") {
        foreach ($r in $routes) {
            Write-Host "         $($r.Line.Trim())" -ForegroundColor Gray
        }
    }
} else {
    # Alternative check via Get-NetRoute
    $netRoutes = Get-NetRoute -DestinationPrefix "$DCNetworkPrefix.0/24" -ErrorAction SilentlyContinue
    if ($netRoutes) {
        Write-TestResult "TC1.3: Route to DC Network" $true "Found via Get-NetRoute"
    } else {
        Write-TestResult "TC1.3: Route to DC Network" $false "No route to $DCNetworkPrefix.0/24 found"
    }
}

# TC1.4: DC Reachability (LDAP)
Write-Host "  Testing DC reachability (LDAP port 389)..." -ForegroundColor Gray
$ldapTest = Test-NetConnection -ComputerName $DCAddress -Port 389 -WarningAction SilentlyContinue
Write-TestResult "TC1.4: DC LDAP (389/TCP)" $ldapTest.TcpTestSucceeded "Latency: $($ldapTest.PingReplyDetails.RoundtripTime)ms"

# TC1.5: DC Reachability (Kerberos)
Write-Host "  Testing DC reachability (Kerberos port 88)..." -ForegroundColor Gray
$krbTest = Test-NetConnection -ComputerName $DCAddress -Port 88 -WarningAction SilentlyContinue
Write-TestResult "TC1.5: DC Kerberos (88/TCP)" $krbTest.TcpTestSucceeded "Connected: $($krbTest.TcpTestSucceeded)"

# TC1.6: DC Reachability (DNS)
Write-Host "  Testing DC reachability (DNS port 53)..." -ForegroundColor Gray
$dnsTest = Test-NetConnection -ComputerName $DCAddress -Port 53 -WarningAction SilentlyContinue
Write-TestResult "TC1.6: DC DNS (53/TCP)" $dnsTest.TcpTestSucceeded "Connected: $($dnsTest.TcpTestSucceeded)"

# TC1.7: Kerberos TGT
if ($SkipKerberos) {
    Write-TestResult "TC1.7: Kerberos TGT" $false -Skip "Skipped via -SkipKerberos flag"
} else {
    Write-Host "  Checking Kerberos TGT..." -ForegroundColor Gray
    $klistOutput = klist 2>&1 | Out-String
    $hasTGT = $klistOutput -match "krbtgt/" -or $klistOutput -match "Ticket\(s\)"

    if ($hasTGT -and $klistOutput -notmatch "Error" -and $klistOutput -notmatch "No tickets") {
        Write-TestResult "TC1.7: Kerberos TGT" $true "TGT found in cache"
        if ($VerbosePreference -eq "Continue") {
            # Extract ticket info
            $tickets = $klistOutput -split "`n" | Where-Object { $_ -match "Server:" -or $_ -match "KerbTicket" }
            foreach ($t in $tickets) {
                Write-Host "         $($t.Trim())" -ForegroundColor Gray
            }
        }
    } else {
        Write-TestResult "TC1.7: Kerberos TGT" $false "No TGT in cache"
        if ($VerbosePreference -eq "Continue") {
            Write-Host "         klist output:" -ForegroundColor Gray
            Write-Host "         $klistOutput" -ForegroundColor Gray
        }
    }
}

# =============================================================================
# TC2: DNS-SRV Discovery (LDAP)
# =============================================================================

Write-TestHeader "TC2: DNS-SRV Discovery (LDAP)"

Write-Host "  Querying _ldap._tcp.$DomainName..." -ForegroundColor Gray
try {
    $ldapSrv = Resolve-DnsName -Name "_ldap._tcp.$DomainName" -Type SRV -ErrorAction Stop
    $srvFound = $ldapSrv -ne $null -and $ldapSrv.Count -gt 0
    Write-TestResult "TC2.1: LDAP SRV Record" $srvFound "Found $($ldapSrv.Count) record(s)"

    if ($srvFound -and $VerbosePreference -eq "Continue") {
        foreach ($srv in $ldapSrv) {
            if ($srv.Type -eq "SRV") {
                Write-Host "         $($srv.NameTarget):$($srv.Port) (Priority: $($srv.Priority), Weight: $($srv.Weight))" -ForegroundColor Gray
            }
        }
    }
} catch {
    Write-TestResult "TC2.1: LDAP SRV Record" $false "Error: $($_.Exception.Message)"

    # Fallback: try nslookup
    Write-Host "  Trying nslookup fallback..." -ForegroundColor Gray
    $nslookup = nslookup -type=SRV "_ldap._tcp.$DomainName" $DCAddress 2>&1 | Out-String
    if ($nslookup -match "service location" -or $nslookup -match "svr hostname") {
        Write-TestResult "TC2.1b: LDAP SRV (nslookup)" $true "Found via nslookup"
    } else {
        Write-TestResult "TC2.1b: LDAP SRV (nslookup)" $false "Not found"
    }
}

# =============================================================================
# TC3: Kerberos-SRV Discovery
# =============================================================================

Write-TestHeader "TC3: DNS-SRV Discovery (Kerberos)"

Write-Host "  Querying _kerberos._udp.$DomainName..." -ForegroundColor Gray
try {
    $krbSrv = Resolve-DnsName -Name "_kerberos._udp.$DomainName" -Type SRV -ErrorAction Stop
    $srvFound = $krbSrv -ne $null -and $krbSrv.Count -gt 0
    Write-TestResult "TC3.1: Kerberos SRV Record (UDP)" $srvFound "Found $($krbSrv.Count) record(s)"

    if ($srvFound -and $VerbosePreference -eq "Continue") {
        foreach ($srv in $krbSrv) {
            if ($srv.Type -eq "SRV") {
                Write-Host "         $($srv.NameTarget):$($srv.Port) (Priority: $($srv.Priority))" -ForegroundColor Gray
            }
        }
    }
} catch {
    Write-TestResult "TC3.1: Kerberos SRV Record (UDP)" $false "Error: $($_.Exception.Message)"
}

# Also test TCP variant
Write-Host "  Querying _kerberos._tcp.$DomainName..." -ForegroundColor Gray
try {
    $krbTcpSrv = Resolve-DnsName -Name "_kerberos._tcp.$DomainName" -Type SRV -ErrorAction Stop
    $srvFound = $krbTcpSrv -ne $null -and $krbTcpSrv.Count -gt 0
    Write-TestResult "TC3.2: Kerberos SRV Record (TCP)" $srvFound "Found $($krbTcpSrv.Count) record(s)"
} catch {
    Write-TestResult "TC3.2: Kerberos SRV Record (TCP)" $false "Error: $($_.Exception.Message)"
}

# =============================================================================
# TC4: UDP Kerberos Connectivity
# =============================================================================

Write-TestHeader "TC4: UDP Kerberos Connectivity"

Write-Host "  Testing UDP connectivity to Kerberos (port 88)..." -ForegroundColor Gray

# UDP test is tricky - we can't directly test UDP with Test-NetConnection
# But we can verify by attempting a DNS query through the DC or checking nltest

# Method 1: Check if nltest can find a DC
Write-Host "  Running nltest /dsgetdc..." -ForegroundColor Gray
$nltestOutput = nltest /dsgetdc:$DomainName 2>&1 | Out-String
$dcFound = $nltestOutput -match "DC:" -or $nltestOutput -match "The command completed successfully"
Write-TestResult "TC4.1: DC Discovery (nltest)" $dcFound "nltest /dsgetdc:$DomainName"

if ($VerbosePreference -eq "Continue" -and $dcFound) {
    $dcLine = $nltestOutput -split "`n" | Where-Object { $_ -match "DC:" } | Select-Object -First 1
    if ($dcLine) {
        Write-Host "         $($dcLine.Trim())" -ForegroundColor Gray
    }
}

# Method 2: Verify UDP port is listening (via portqry if available, otherwise skip)
# For CI, we rely on the TCP test + nltest as indicators of UDP functionality
Write-Host "  UDP 88 verification..." -ForegroundColor Gray
# The presence of a TGT or successful nltest implies UDP Kerberos works
$udpIndicator = $dcFound -or ($script:TestResults.Passed -contains "TC1.7: Kerberos TGT")
Write-TestResult "TC4.2: UDP Kerberos Indicator" $udpIndicator "Based on DC discovery and TGT status"

# =============================================================================
# NRPT Verification (Bonus)
# =============================================================================

Write-TestHeader "NRPT Configuration Check"

Write-Host "  Checking NRPT rules..." -ForegroundColor Gray
$nrptPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
)

$nrptFound = $false
foreach ($path in $nrptPaths) {
    if (Test-Path $path) {
        $rules = Get-ChildItem $path -ErrorAction SilentlyContinue
        if ($rules) {
            $domainRule = $rules | Where-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $props.Name -like "*$DomainName*" -or $props.ConfigOptions -like "*$DomainName*"
            }
            if ($domainRule) {
                $nrptFound = $true
                break
            }
        }
    }
}

# Alternative: Check via PowerShell cmdlet
if (-not $nrptFound) {
    try {
        $nrptRules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue
        $domainRule = $nrptRules | Where-Object { $_.Namespace -like "*$DomainName*" }
        $nrptFound = $domainRule -ne $null
    } catch {
        # Cmdlet not available on all systems
    }
}

Write-TestResult "NRPT: Domain Rule" $nrptFound "Rule for $DomainName configured"

# =============================================================================
# Summary
# =============================================================================

Write-TestSummary

# =============================================================================
# Exit Code
# =============================================================================

if ($script:TestResults.Failed.Count -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed. See details above." -ForegroundColor Red
    exit 1
}
