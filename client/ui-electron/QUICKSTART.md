# Quick Start Guide

## Getting Started in 3 Steps

### 1. Install Dependencies

```bash
cd /home/pascal/Git/Netbird/netbird/client/ui-electron
npm install
```

This will install all required packages including:
- Electron 28
- React 18
- TypeScript 5
- Tailwind CSS
- Framer Motion
- gRPC libraries

### 2. Start Development Server

```bash
npm run dev
```

This command:
- Starts Vite dev server on `http://localhost:5173`
- Compiles Electron TypeScript code
- Launches Electron window
- Enables hot reload for React components

### 3. Start Using the App

The app will open with:
- Modern glass-themed interface
- System tray icon
- Real-time connection status
- Full feature access

## What You'll See

### Dashboard Page
- Connection status with animated icon
- Connect/Disconnect button
- Quick feature overview
- Configuration summary

### Networks Page
- List of available networks
- Select/deselect networks
- View domains and IPs
- Filter by type

### Settings Page
- Connection configuration
- Feature toggles (SSH, Rosenpass, etc.)
- Advanced settings
- Save changes instantly

### Profiles Page
- View all profiles
- Switch between profiles
- Active profile indicator

### Debug Page
- Create debug bundles
- Anonymization option
- Export diagnostics

## Development Tips

### File Structure
```
src/
├── App.tsx           # Main app with routing
├── store/            # Zustand state management
└── pages/            # Individual page components
```

### Making Changes

1. **UI Changes**: Edit files in `src/pages/` - auto-reloads
2. **State Logic**: Modify `src/store/useStore.ts`
3. **Electron Main**: Edit `electron/main.ts` - requires restart
4. **gRPC Client**: Update `electron/grpc/client.ts`
5. **Styles**: Customize `tailwind.config.js`

### Testing Connection

Ensure NetBird daemon is running:

```bash
netbird status
```

Should show daemon is operational.

## Building for Production

### Quick Build

```bash
npm run build
npm run build:linux
```

Creates distributable packages in `release/` directory.

### Packages Created

- **AppImage**: Portable Linux application
- **.deb**: Debian/Ubuntu package
- **Unpacked**: Direct executable

## Troubleshooting

### Port 5173 already in use
```bash
kill $(lsof -t -i:5173)
npm run dev
```

### Cannot connect to daemon
```bash
systemctl status netbird
netbird service start  # if not running
```

### Build errors
```bash
rm -rf node_modules package-lock.json dist
npm install
npm run build
```

## Next Steps

1. **Customize Theme**: Edit `tailwind.config.js` colors
2. **Add Features**: Extend pages in `src/pages/`
3. **Add Icons**: Place PNGs in `assets/` directory
4. **Test Build**: Run `npm run build:linux`

## Resources

- **NetBird Docs**: https://docs.netbird.io
- **Electron Docs**: https://electronjs.org/docs
- **React Docs**: https://react.dev
- **Tailwind Docs**: https://tailwindcss.com

## Support

- GitHub Issues: https://github.com/netbirdio/netbird/issues
- NetBird Slack: Join via netbird.io

---

Happy coding! Enjoy the modern NetBird UI.
