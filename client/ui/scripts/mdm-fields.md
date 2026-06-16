# MDM dev cheatsheet (macOS)

Edits `/Library/Managed Preferences/io.netbird.client.plist`. Daemon picks up
changes within ≤60s; no restart needed.

Run the interactive TUI:

```bash
./mdm-toggle.sh tui
```

Keys: number to edit a field, **k** to kick the daemon, **c** to clear the
plist, **l** to view recent MDM log lines, **r** to refresh, **q** to quit.

## Known keys

- Strings/ints: `managementURL`, `preSharedKey`, `wireguardPort`, `splitTunnelMode` (`allow`/`disallow`)
- Array: `splitTunnelApps`
- Bools: `rosenpassEnabled`, `rosenpassPermissive`, `disableClientRoutes`, `disableServerRoutes`, `allowServerSSH`, `disableAutoConnect`, `blockInbound`, `disableMetricsCollection`
- Feature gates: `disableAdvancedView`, `disableProfiles`, `disableNetworks`, `disableUpdateSettings` (true = hide; false/unset = allow)
