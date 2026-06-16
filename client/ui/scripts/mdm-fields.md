# MDM dev cheatsheet

Two platform helpers, same field set. The daemon's MDM ticker picks up changes
within ≤60s and restarts the engine in-process — no service restart needed.

## macOS — `mdm-toggle.sh`

Edits `/Library/Managed Preferences/io.netbird.client.plist`.

```bash
./mdm-toggle.sh tui
```

Keys: number to edit a field, **k** to kick the daemon, **c** to clear the
plist, **l** to view recent MDM log lines, **r** to refresh, **q** to quit.

## Windows — `mdm-toggle.ps1`

**▶ [Launch the TUI](mdm-tui.bat)** (double-click `mdm-tui.bat` — it self-elevates).

Edits `HKLM\Software\Policies\NetBird` (the key Group Policy / Intune ADMX /
a Registry CSP profile would populate — see `client/mdm/policy_windows.go`).
Self-elevates (HKLM writes need admin). Or run it directly:

```powershell
.\mdm-toggle.ps1
```

Same keys as the macOS TUI: number to edit a field, **k** to kick the daemon,
**c** to clear the policy key, **r** to refresh, **q** to quit. Registry type
mapping (mirrors `readRegistryValue`): `string → REG_SZ`, `integer → REG_DWORD`,
`bool → REG_DWORD` (1=true / 0=false), `array → REG_MULTI_SZ`. Value names are
case-insensitive (the loader canonicalises against the known key set);
service: `Netbird`.

## Known keys

- Strings/ints: `managementURL`, `preSharedKey`, `wireguardPort`, `splitTunnelMode` (`allow`/`disallow`)
- Array: `splitTunnelApps`
- Bools: `rosenpassEnabled`, `rosenpassPermissive`, `disableClientRoutes`, `disableServerRoutes`, `allowServerSSH`, `disableAutoConnect`, `blockInbound`, `disableMetricsCollection`
- Feature gates: `disableAdvancedView`, `disableProfiles`, `disableNetworks`, `disableUpdateSettings` (true = hide; false/unset = allow)
