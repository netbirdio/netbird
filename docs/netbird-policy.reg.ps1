#requires -Version 5.1
<#
.SYNOPSIS
  Push the NetBird MDM policy to a Windows device via JumpCloud Commands
  by importing a sidecar netbird-policy.reg file.

.DESCRIPTION
  Windows counterpart of docs/netbird-macos.sh. Outcome:
  HKLM\Software\Policies\NetBird populated from the attached
  netbird-policy.reg file, daemon picks up the change via the
  1-minute MDM reload ticker.

  Deployment:
    1. Admin Console -> Device Management -> Commands -> +.
    2. Type: Windows PowerShell. Run as: SYSTEM.
    3. Paste this file verbatim into the command body.
    4. In the same command, attach `netbird-policy.reg` as a file.
       JumpCloud copies attached files into the command's working
       directory before invoking the script, so `$PSScriptRoot` or
       Get-Location resolves to where the .reg lives.
    5. Bind to the target system group, save, run.

  Producing the .reg file:
    On a reference machine, after configuring the policy values either
    via gpedit (GPO) or manual `reg add`, export with:

        reg export "HKLM\Software\Policies\NetBird" netbird-policy.reg /y

    Then attach the resulting file to the JumpCloud command.

  Semantics:
    - The script nukes the existing HKLM\Software\Policies\NetBird key
      before importing the .reg, so the .reg is the SINGLE SOURCE OF
      TRUTH. Any value present in the registry but absent from the .reg
      is removed. This is what an MDM admin almost always wants.
    - Setting the .reg to an empty (header-only) file effectively unsets
      the policy.

  Idempotency: re-running the script with the same .reg is a no-op from
  the daemon's perspective (values identical → 1-min ticker sees no
  diff → engine not restarted).

  Exit codes: 0 = success; 1 = .reg missing or reg.exe error.
#>

$ErrorActionPreference = "Stop"

$RegFileName = "netbird-policy.reg"
$RegKey      = "HKLM\Software\Policies\NetBird"

# Resolve the attached .reg file: JumpCloud copies command attachments
# into C:\Windows\Temp\ before invoking the script. Cwd / $PSScriptRoot
# fallbacks cover the local-dev case where you might dot-source this
# from elsewhere.
$candidates = @(
    (Join-Path "$env:WINDIR\Temp" $RegFileName)
    (Join-Path (Get-Location)     $RegFileName)
    (Join-Path $PSScriptRoot      $RegFileName)
) | Where-Object { Test-Path $_ }

if ($candidates.Count -eq 0) {
    Write-Error "[netbird-mdm] $RegFileName not found in working directory or `$PSScriptRoot. Attach the file to the JumpCloud command."
    exit 1
}
$regFile = $candidates[0]
Write-Host "[netbird-mdm] using $regFile"

# Wipe the existing policy key so the .reg is authoritative.
$existed = Test-Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\NetBird"
if ($existed) {
    & reg.exe delete $RegKey /f | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[netbird-mdm] failed to clear $RegKey before import (exit $LASTEXITCODE)"
        exit 1
    }
    Write-Host "[netbird-mdm] cleared previous values under $RegKey"
}

# Import. reg.exe writes both data and (re-)creates the key if needed.
& reg.exe import $regFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "[netbird-mdm] reg import failed (exit $LASTEXITCODE)"
    exit 1
}

# Audit dump so the JumpCloud per-execution log captures the applied state.
Write-Host "[netbird-mdm] final policy state under $RegKey :"
& reg.exe query $RegKey /s

# Daemon's 1-min reload ticker picks up the change automatically.
# Uncomment to force immediate convergence (skips the ticker wait):
#   Restart-Service netbird -Force -ErrorAction SilentlyContinue

exit 0
