# NetBird Electron UI

A modern, beautiful Electron-based desktop UI for NetBird VPN built with React, TypeScript, and Tailwind CSS.

## Features

- **Modern Glass Design**: Beautiful icy blue theme with glassmorphism effects
- **System Tray Integration**: Runs in background with system tray icon
- **Real-time Status**: Live connection status updates
- **Network Management**: Select and manage network routes
- **Profile Management**: Switch between multiple NetBird profiles
- **Advanced Settings**: Full configuration control
- **Debug Tools**: Create debug bundles for troubleshooting

## Technology Stack

- **Electron 28**: Desktop application framework
- **React 18**: UI library
- **TypeScript 5**: Type-safe development
- **Tailwind CSS**: Utility-first styling
- **Framer Motion**: Smooth animations
- **Zustand**: State management
- **gRPC**: Daemon communication via @grpc/grpc-js
- **Lucide React**: Modern icon library

## Prerequisites

- Node.js 18+ and npm
- NetBird daemon running (`netbird service start`)
- Linux with Unix domain socket support (or Windows with TCP)

## Installation

```bash
cd /home/pascal/Git/Netbird/netbird/client/ui-electron
npm install
```

## Development

Run in development mode with hot reload:

```bash
npm run dev
```

This starts:
1. Vite dev server on port 5173 (React app)
2. Electron main process

## Building

### Build for current platform

```bash
npm run build
```

### Build for Linux

```bash
npm run build:linux
```

Generates AppImage and .deb packages in `release/` directory.

### Build for all platforms

```bash
npm run build:all
```

## Project Structure

```
ui-electron/
├── electron/              # Electron main process
│   ├── main.ts           # Main process entry point
│   ├── preload.ts        # Preload script for IPC
│   └── grpc/
│       └── client.ts     # gRPC client for daemon communication
├── src/                  # React application
│   ├── App.tsx          # Main app component
│   ├── main.tsx         # React entry point
│   ├── index.css        # Global styles
│   ├── store/
│   │   └── useStore.ts  # Zustand state management
│   └── pages/           # Page components
│       ├── Dashboard.tsx
│       ├── Settings.tsx
│       ├── Networks.tsx
│       ├── Profiles.tsx
│       └── Debug.tsx
├── assets/              # Icons and images
├── package.json
├── tsconfig.json        # TypeScript config (renderer)
├── tsconfig.electron.json  # TypeScript config (main)
├── vite.config.ts       # Vite config
├── tailwind.config.js   # Tailwind CSS config
└── postcss.config.js    # PostCSS config
```

## Design System

### Colors

- **Icy Blue**: `#a3d7e5` - Primary accent color
- **Dark Background**: `#121218` - Main background
- **Dark Card**: `#1c1c23` - Card backgrounds
- **Text Light**: `#f8f8fc` - Primary text
- **Text Muted**: `#a0a0aa` - Secondary text

### Components

- Glass morphism cards with blur effects
- Smooth page transitions with Framer Motion
- Icy blue glow effects on active elements
- Custom scrollbars
- Modern toggle switches and checkboxes

## gRPC Communication

The app communicates with the NetBird daemon via gRPC:

- **Unix Socket** (Linux/macOS): `unix:///var/run/netbird.sock`
- **TCP** (Windows): `localhost:41731`

All daemon operations are exposed through the Electron IPC bridge for security.

## System Tray

The system tray provides quick access to:

- Connection status
- Connect/Disconnect
- Settings menu
- Networks
- Debug bundle creation
- Quit

Menu items update dynamically based on daemon state.

## Development Notes

### Hot Reload

Vite provides hot module replacement for the React app. Changes to Electron main process require restart.

### Debugging

- React DevTools: Available in development mode
- Electron DevTools: Opens automatically in dev mode
- gRPC logging: Check console for daemon communication

### Type Safety

Full TypeScript coverage with strict mode enabled. The preload script exposes typed APIs to the renderer process.

## Customization

### Theme

Edit `tailwind.config.js` to customize colors:

```js
colors: {
  icy: {
    blue: '#a3d7e5',  // Change primary color
  },
}
```

### Icons

System tray icons should be placed in `assets/` directory:

- `tray-icon-connected.png` - Connected state
- `tray-icon-disconnected.png` - Disconnected state
- `tray-icon-connecting.png` - Connecting state
- `tray-icon-error.png` - Error state

## Deployment

### Linux

AppImage and .deb packages can be distributed directly. The app will:

1. Auto-launch on system startup (if configured)
2. Run in system tray
3. Connect to local NetBird daemon

### Permissions

The app requires:

- Network access (for gRPC communication)
- File system access (for debug bundles)
- System tray access

## Troubleshooting

### Cannot connect to daemon

Ensure NetBird daemon is running:

```bash
systemctl status netbird
# or
netbird status
```

### gRPC errors

Check daemon socket permissions:

```bash
ls -la /var/run/netbird.sock
```

### Build errors

Clear node_modules and reinstall:

```bash
rm -rf node_modules package-lock.json
npm install
```

## Contributing

This is a modern alternative UI for NetBird. Improvements welcome!

### Code Style

- Use TypeScript strict mode
- Follow React hooks best practices
- Use Tailwind utility classes
- Implement smooth transitions with Framer Motion

## License

Same as NetBird project (BSD 3-Clause).

## Credits

- **NetBird**: [github.com/netbirdio/netbird](https://github.com/netbirdio/netbird)
- **Design**: Modern glass morphism with icy blue theme
- **Icons**: Lucide React

---

**Note**: This is a community-contributed modern UI alternative. The official NetBird UI is built with Fyne (Go).
