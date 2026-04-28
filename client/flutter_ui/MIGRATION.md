# Flutter UI Migration

## Current Boundary

Keep the daemon as-is and replace only the desktop UI process. The Flutter app
should continue to talk to `DaemonService` from `client/proto/daemon.proto`.

The current UI is not a simple settings window. It owns:

- tray/menu-bar state and nested menu actions
- gRPC connection management and event subscription
- connect, disconnect, login, and session-expired flows
- profile switching, deregistration, and profile windows
- network route and exit-node selection
- advanced settings
- debug bundle creation and upload status dialogs
- enforced update notifications and progress windows
- OS sleep/wake notification to the daemon
- single-instance signaling and quick-actions windows

## Phases

1. Scaffold and generated gRPC client
   - Done: generated Dart stubs from `client/proto/daemon.proto`.
   - Done: app defaults to a gRPC-backed implementation and keeps
     `--fake-daemon` for UI-only work.
   - Remaining: replace the development user agent suffix with the release
     version at build time.

2. Core connection parity
   - Done: status polling and `SubscribeEvents` refresh hooks.
   - Done: `connect()` runs `Login` → optional SSO browser handoff via
     `openExternalUrl` → `WaitSSOLogin` → `Up`, with an `awaitingLogin` snapshot
     state and a banner that exposes the verification URI and user code.
   - Done: `disconnect()` calls `Down`.
   - Match current daemon address defaults:
     - Windows: `tcp://127.0.0.1:41731`
     - Unix-like desktop: `unix:///var/run/netbird.sock`

3. Settings, profiles, and networks
   - Done: `GetConfig`/`SetConfig` for the toggleable settings (auto-connect,
     allow SSH, quantum resistance, lazy connections, block inbound,
     notifications). Read-only fields (management URL, interface, port, MTU)
     still need editable forms.
   - Done: profile add/switch/remove/logout via `AddProfile`,
     `SwitchProfile`, `RemoveProfile`, `Logout`.
   - Done: network list with overlap filtering, per-route
     `SelectNetworks`/`DeselectNetworks`, and exit-node single-selection.

4. Desktop integration
   - Done: tray icon and menu via `tray_manager` (status header, profile,
     Connect/Disconnect, Show window, Quit) with status-aware icons that fall
     back to template variants on macOS.
   - Done: window lifecycle via `window_manager` — close hides instead of
     exiting; tray "Quit" actually destroys the window.
   - Done: native notifications via `local_notifier`, fed by the daemon's
     `SubscribeEvents` stream and gated by the `notifications` setting (with
     CRITICAL severity always firing).
   - Done: browser launch and clipboard via `Process.run` and
     `flutter/services` Clipboard.
   - Remaining: file/folder reveal for debug bundles, single-instance
     signaling, quick-actions invocation, and sleep/wake forwarding through
     `NotifyOSLifecycle`. Settings/Networks submenus on the tray are deferred
     until the window-side flows are stable.
   - Note: `local_notifier` uses macOS's deprecated `NSUserNotificationCenter`
     (warns at build time). Plan to swap to `flutter_local_notifications`
     before release.

5. Debug and update flows
   - Done: rich debug bundle screen with anonymize, system-info, upload (URL),
     and run-with-trace + duration. State machine drives `GetLogLevel` →
     `SetLogLevel(TRACE)` → `Down` → `SetSyncResponsePersistence` → `Up` →
     progress over duration → `StopCPUProfile` → `DebugBundle`, with restore
     of original log level and persistence in a finally. Result dialog covers
     uploaded, upload-failed, and local-only outcomes with copy/open actions.
   - Done: enforced-update modal triggered by daemon `progress_window=show`
     metadata. Polls `GetInstallerResult` with a 15-min timeout, blocks close
     for 10 s, then surfaces success (auto-close) or failure (error message).
   - Remaining: hook a "Check for updates" / "Install now" button into the
     About surface that calls `TriggerUpdate` directly.

6. Release pipeline
   - Update `.github/workflows/release.yml` UI build steps.
   - Update `client/netbird.wxs`, `release_files/install.sh`, and
     `release_files/ui-post-install.sh` where they assume the Go UI artifact.
   - Update updater restart behavior in `client/internal/updater/installer`.
   - Preserve public artifact names until installers and updater logic are
     intentionally migrated.

## RPCs Used By The Current UI

The first production implementation should cover:

- `Status`, `Up`, `Down`
- `Login`, `WaitSSOLogin`, `Logout`
- `GetConfig`, `SetConfig`, `GetFeatures`
- `SubscribeEvents`
- `ListNetworks`, `SelectNetworks`, `DeselectNetworks`
- `ListProfiles`, `AddProfile`, `SwitchProfile`, `RemoveProfile`,
  `GetActiveProfile`
- `DebugBundle`, `GetLogLevel`, `SetLogLevel`, `SetSyncResponsePersistence`,
  `StartCPUProfile`, `StopCPUProfile`
- `TriggerUpdate`, `GetInstallerResult`
- `NotifyOSLifecycle`

## Risk Register

- Desktop tray support differs sharply across Windows, macOS, and Linux.
- Linux app indicators and desktop-session startup need distro-level testing.
- The updater currently restarts `netbird-ui` by process/app name on Windows and
  macOS, so artifact naming changes must be coordinated.
- Dart gRPC over Unix domain sockets must be validated against the daemon's
  existing `unix://` address behavior.
- Flutter desktop packaging is separate from Go builds, so release CI needs a
  new toolchain and cache strategy.
