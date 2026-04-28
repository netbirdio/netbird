# NetBird Flutter UI

This is the migration workspace for a Flutter-based replacement for `client/ui`.
The existing Go/Fyne UI remains the production UI until this package reaches
feature and release-pipeline parity.

## Scope

The first target is the desktop UI only. The NetBird daemon, service lifecycle,
network engine, and daemon gRPC API stay in Go.

Initial parity target:

- tray/menu-bar entry with connection status and connect/disconnect actions
- settings and feature flags backed by `DaemonService.GetConfig` and `SetConfig`
- profile management
- network and exit-node selection
- daemon event subscription and desktop notifications
- login/session-expired flow
- debug bundle flow
- enforced-update progress window
- Windows, macOS, and Linux packaging integration

## Bootstrap

Flutter and Dart are not committed into this repository. After installing the
Flutter SDK, run:

```sh
cd client/flutter_ui
bash tool/bootstrap.sh
bash tool/generate_proto.sh
flutter run -d macos -- --daemon-addr=unix:///var/run/netbird.sock
```

Use `-d windows` or `-d linux` on those platforms. The Windows daemon address is
currently `tcp://127.0.0.1:41731`.

For UI-only development without a daemon, run:

```sh
flutter run -d macos -- --fake-daemon
```

## Layout

- `lib/main.dart`: app entry point and command-line flag parsing
- `lib/src/app_shell.dart`: first-pass desktop shell
- `lib/src/daemon_client.dart`: daemon boundary with fake and gRPC-backed clients
- `lib/src/models.dart`: UI-facing models independent from generated protobufs
- `lib/src/generated/`: generated Dart protobuf and gRPC files
- `tool/bootstrap.sh`: creates Flutter desktop platform folders once Flutter is installed
- `tool/generate_proto.sh`: generates Dart gRPC bindings from `client/proto/daemon.proto`
- `MIGRATION.md`: parity plan and release integration checklist
