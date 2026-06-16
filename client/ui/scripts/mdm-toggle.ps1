<#
.SYNOPSIS
  Interactive tester for NetBird's MDM policy on Windows.

.DESCRIPTION
  Edits HKLM\Software\Policies\NetBird (the same registry key the OS would
  populate from Group Policy / Intune ADMX ingestion / a Registry CSP profile,
  see client/mdm/policy_windows.go). The MDM ticker re-reads the key within
  <=60s; the daemon restarts the engine itself in-process - no service restart
  needed for a change to take effect (the [k] kick only forces an immediate
  re-read or recovers a wedged daemon).

  Value-type mapping (mirrors readRegistryValue):
    string  -> REG_SZ
    integer -> REG_DWORD
    bool    -> REG_DWORD (1=true, 0=false)   GetBool treats !=0 as true
    array   -> REG_MULTI_SZ

  Requires elevation (writing HKLM). Re-launches itself elevated if needed.

  Keys: number to edit a field, [k] kick the daemon, [c] clear the whole
  policy key, [r] refresh, [q] quit.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$PolicyPath = 'HKLM:\Software\Policies\NetBird'

# Known keys and their registry types. Order drives the TUI numbering.
$Fields = @(
    @{ Key = 'managementURL';            Type = 'string'  }
    @{ Key = 'preSharedKey';             Type = 'string'  }
    @{ Key = 'wireguardPort';            Type = 'integer' }
    @{ Key = 'splitTunnelMode';          Type = 'string'  }  # allow / disallow
    @{ Key = 'splitTunnelApps';          Type = 'array'   }
    @{ Key = 'rosenpassEnabled';         Type = 'bool'    }
    @{ Key = 'rosenpassPermissive';      Type = 'bool'    }
    @{ Key = 'disableClientRoutes';      Type = 'bool'    }
    @{ Key = 'disableServerRoutes';      Type = 'bool'    }
    @{ Key = 'allowServerSSH';           Type = 'bool'    }
    @{ Key = 'disableAutoConnect';       Type = 'bool'    }
    @{ Key = 'blockInbound';             Type = 'bool'    }
    @{ Key = 'disableMetricsCollection'; Type = 'bool'    }
    @{ Key = 'disableAdvancedView';      Type = 'bool'    }
    @{ Key = 'disableProfiles';          Type = 'bool'    }
    @{ Key = 'disableNetworks';          Type = 'bool'    }
    @{ Key = 'disableUpdateSettings';    Type = 'bool'    }
)

# ---- elevation --------------------------------------------------------------

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host 'Elevation required for HKLM writes - relaunching as admin...' -ForegroundColor Yellow
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit 0
}

# ---- ANSI helpers (VT; conhost on Win10+ and Windows Terminal support it) ----

$IsTty = -not [Console]::IsOutputRedirected
$e = [char]27
function C($code) { if ($IsTty) { "${e}[${code}m" } else { '' } }
$Reset = C '0'; $Bold = C '1'; $Dim = C '2'
$Green = C '32'; $Red = C '31'; $Yellow = C '33'; $Cyan = C '36'

# ---- service ----------------------------------------------------------------

function Restart-Daemon {
    $svc = Get-Service -Name 'Netbird', 'netbird' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $svc) { Write-Host 'Netbird service not found.' -ForegroundColor Red; return }
    Write-Host "restarting service ($($svc.Name))..."
    Restart-Service -Name $svc.Name -Force
}

# ---- registry read/write ----------------------------------------------------

function Ensure-PolicyKey {
    if (-not (Test-Path $PolicyPath)) { New-Item -Path $PolicyPath -Force | Out-Null }
}

function Read-Value {
    param([string]$Key)
    if (-not (Test-Path $PolicyPath)) { return $null }
    $item = Get-ItemProperty -Path $PolicyPath -Name $Key -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Key
}

function Set-Value {
    param([string]$Key, [string]$Type, $Value)
    Ensure-PolicyKey
    switch ($Type) {
        'array'   { Set-ItemProperty -Path $PolicyPath -Name $Key -Value ([string[]]$Value) -Type MultiString }
        'integer' { Set-ItemProperty -Path $PolicyPath -Name $Key -Value ([int]$Value) -Type DWord }
        'bool'    { Set-ItemProperty -Path $PolicyPath -Name $Key -Value ([int]$Value) -Type DWord }
        default   { Set-ItemProperty -Path $PolicyPath -Name $Key -Value ([string]$Value) -Type String }
    }
}

function Clear-Value {
    param([string]$Key)
    if (Test-Path $PolicyPath) {
        Remove-ItemProperty -Path $PolicyPath -Name $Key -ErrorAction SilentlyContinue
    }
}

function Clear-PolicyKey {
    if (Test-Path $PolicyPath) {
        Remove-Item -Path $PolicyPath -Recurse -Force
        Write-Host "removed $PolicyPath"
    } else {
        Write-Host '(already absent)'
    }
}

# ---- TUI --------------------------------------------------------------------

function Render-Value {
    param($Raw, [string]$Type)
    if ($null -eq $Raw -or ($Raw -is [string] -and $Raw -eq '')) {
        return "$Dim-$Reset"
    }
    switch ($Type) {
        'bool' {
            if ([int]$Raw -ne 0) { "${Green}[+] true$Reset" } else { "${Red}[-] false$Reset" }
        }
        'array' { "${Cyan}[$($Raw -join ' ')]$Reset" }
        default { "$Yellow$Raw$Reset" }
    }
}

function Render-Screen {
    Clear-Host
    Write-Host "$Bold==== NetBird MDM Tester (Windows) ====$Reset"
    Write-Host "${Dim}key:$Reset $PolicyPath`n"
    for ($i = 0; $i -lt $Fields.Count; $i++) {
        $f = $Fields[$i]
        $raw = Read-Value $f.Key
        $num = ('[{0,2}]' -f ($i + 1))
        $val = Render-Value $raw $f.Type
        Write-Host ("  $Bold$num$Reset {0,-30} {1} $Dim({2})$Reset" -f $f.Key, $val, $f.Type)
    }
    Write-Host ''
    Write-Host "  ${Bold}[k]$Reset kick daemon   ${Bold}[c]$Reset clear key   ${Bold}[r]$Reset refresh   ${Bold}[q]$Reset quit"
    Write-Host ''
}

function Edit-Field {
    param([int]$Index)
    if ($Index -lt 1 -or $Index -gt $Fields.Count) { Write-Host '  (out of range)'; Start-Sleep -Milliseconds 600; return }
    $f = $Fields[$Index - 1]
    $cur = Read-Value $f.Key
    switch ($f.Type) {
        'bool' {
            # Cycle: unset -> true -> false -> unset
            if ($null -eq $cur)      { Set-Value $f.Key 'bool' 1 }
            elseif ([int]$cur -ne 0) { Set-Value $f.Key 'bool' 0 }
            else                     { Clear-Value $f.Key }
        }
        'array' {
            Write-Host "  current: $($cur -join ' ')"
            $line = Read-Host '  new array (space-separated, empty to unset)'
            if ([string]::IsNullOrWhiteSpace($line)) { Clear-Value $f.Key }
            else { Set-Value $f.Key 'array' ($line -split '\s+' | Where-Object { $_ }) }
        }
        default {
            Write-Host "  current: $cur"
            $line = Read-Host "  new $($f.Type) (empty to unset)"
            if ([string]::IsNullOrWhiteSpace($line)) { Clear-Value $f.Key }
            else { Set-Value $f.Key $f.Type $line }
        }
    }
}

Write-Host 'starting MDM tester (q to quit)'
while ($true) {
    Render-Screen
    $choice = Read-Host '>'
    switch -Regex ($choice) {
        '^(q|quit|exit)$' { Write-Host 'bye'; return }
        '^(k|kick)$'      { Restart-Daemon; Start-Sleep -Milliseconds 600 }
        '^(c|clear)$'     { Clear-PolicyKey; Start-Sleep -Milliseconds 600 }
        '^(r|)$'          { }  # redraw
        '^\d+$'           { Edit-Field ([int]$choice) }
        default           { Write-Host '  (unknown - number to edit, k/c/r/q)'; Start-Sleep -Milliseconds 600 }
    }
}
