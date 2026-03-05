# NetBird Tauri UI

## Prerequisites

- Rust (https://rustup.rs)
- Node.js 18+
- Linux: `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libappindicator3-dev librsvg2-dev patchelf protobuf-compiler`

## Build & Run

```bash
# Frontend
cd frontend && npm install && npm run build && cd ..

# Backend (debug)
cd src-tauri && cargo build

# Run
RUST_LOG=info ./src-tauri/target/debug/netbird-ui

# Release build
cd src-tauri && cargo build --release
./src-tauri/target/release/netbird-ui
```

The NetBird daemon must be running (`netbird service start`).
