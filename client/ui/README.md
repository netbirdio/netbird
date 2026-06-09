# NetBird desktop UI (Wails3 + React)

Replaces `client/ui` (Fyne). One binary on Windows / macOS / Linux,
talks to the NetBird daemon over gRPC, renders a React frontend in a
WebView.

## Prerequisites

- Go ≥ 1.25, Node ≥ 20, **pnpm** (`corepack enable && corepack prepare pnpm@latest --activate`)
- `wails3` CLI: `go install github.com/wailsapp/wails/v3/cmd/wails3@latest`
- `task`: `go install github.com/go-task/task/v3/cmd/task@latest`
- A running NetBird daemon (default: `unix:///var/run/netbird.sock`,
  Windows `tcp://127.0.0.1:41731`)
- Linux only: `libwebkitgtk-6.0-dev`, `libgtk-4-dev`, `libsoup-3.0-dev`

## Develop without rebuilding

```bash
cd client/ui
task dev
```

`task dev` runs Vite (port 9245) + the Go binary + a `*.go` watcher.
Frontend edits hot-reload instantly. Go edits trigger a rebuild and
relaunch. Pass daemon flags after `--`:

```bash
task dev -- --daemon-addr=tcp://127.0.0.1:41731
```

For pure UI work (no native window, fastest loop):

```bash
cd frontend && pnpm dev
```

## Production build

```bash
task build
```

Output in `bin/`. Frontend assets are embedded into the binary.

### Cross-compile Windows from Linux

Install the mingw-w64 toolchain once:

```bash
sudo apt install gcc-mingw-w64-x86-64           # Debian/Ubuntu
sudo dnf install mingw64-gcc                    # Fedora
sudo pacman -S mingw-w64-gcc                    # Arch
```

Then:

```bash
CGO_ENABLED=1 task windows:build
```

Produces `bin/netbird-ui.exe`. macOS cross-compile from Linux is not
supported (signing and notarization need a real Mac).

### Windows console build (logs in the terminal)

Default `windows:build` links the binary as a Windows GUI app, which
detaches from the launching console — `logrus` output, `fmt.Println`,
and panics go nowhere visible. To debug tray/event/daemon issues:

```bash
CGO_ENABLED=1 task windows:build:console
```

Produces `bin/netbird-ui-console.exe`. Run it from `cmd.exe` /
PowerShell / Windows Terminal and stdout/stderr land in that
terminal. Same flag works on a native Windows build (drop the
`CGO_ENABLED=1` if your toolchain already has it set).

## Regenerating bindings

When a Go service signature changes:

```bash
wails3 generate bindings
```

`task dev` does this automatically on `*.go` save.

## Tray icons

Source SVGs live in `assets/svg/` (state.svg + state-macos.svg). After editing
any SVG, rasterize to the PNGs the Go side embeds:

```bash
task common:generate:tray:icons
```

Requires Inkscape. Commit the resulting `assets/*.png` files alongside the
SVG change so CI doesn't need Inkscape installed.
