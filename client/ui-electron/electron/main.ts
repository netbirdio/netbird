import { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { DaemonClient } from './grpc/client';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let daemonClient: DaemonClient;
let isQuitting = false;
let cachedProfiles: string = ''; // Cache profiles to avoid menu rebuilding

const isDev = !app.isPackaged;

// Daemon address - Unix socket on Linux/BSD/macOS, TCP on Windows
const DAEMON_ADDR = process.platform === 'win32'
  ? 'localhost:41731'
  : 'unix:///var/run/netbird.sock';

// Helper function to get NetBird config directory
function getNetBirdConfigDir(): string {
  const homeDir = os.homedir();
  return path.join(homeDir, '.config', 'netbird');
}

// Helper function to read active profile from filesystem
function readActiveProfileFromFS(): string | null {
  try {
    const configDir = getNetBirdConfigDir();
    const activeProfilePath = path.join(configDir, 'active_profile.txt');

    if (fs.existsSync(activeProfilePath)) {
      const profileName = fs.readFileSync(activeProfilePath, 'utf-8').trim();
      return profileName || 'default';
    }
    return 'default';
  } catch (error) {
    console.error('Error reading active profile from filesystem:', error);
    return null;
  }
}

// Helper function to read profile state (email) from filesystem
function readProfileState(profileName: string): { email?: string } | null {
  try {
    const configDir = getNetBirdConfigDir();
    const stateFilePath = path.join(configDir, `${profileName}.state.json`);

    if (fs.existsSync(stateFilePath)) {
      const stateContent = fs.readFileSync(stateFilePath, 'utf-8');
      return JSON.parse(stateContent);
    }
    return null;
  } catch (error) {
    console.error(`Error reading profile state for ${profileName}:`, error);
    return null;
  }
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    backgroundColor: '#121218',
    show: false,
    frame: true,
    autoHideMenuBar: true, // Hide the menu bar (File, Edit, View, etc.)
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // Remove the application menu completely
  mainWindow.setMenuBarVisibility(false);

  // Load the app
  if (isDev) {
    const port = process.env.VITE_PORT || '5173';
    mainWindow.loadURL(`http://localhost:${port}`);
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  // Hide instead of close
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
    }
  });
}

async function createTray() {
  // Create tray icon
  const iconPath = path.join(__dirname, '../../assets/tray-icon-disconnected.png');
  const icon = nativeImage.createFromPath(iconPath);

  tray = new Tray(icon.resize({ width: 22, height: 22 }));
  tray.setToolTip('NetBird - Disconnected');

  // Update tray menu
  updateTrayMenu(false);

  // Show window on tray click
  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.hide();
      } else {
        mainWindow.show();
        mainWindow.focus();
      }
    } else {
      createWindow();
    }
  });
}

async function updateTrayMenu(connected: boolean) {
  if (!tray) return;

  // Get profiles for dynamic submenu
  let profileMenuItems: any[] = [];
  let profilesHash = '';
  try {
    const username = require('os').userInfo().username;
    const profilesResponse = await daemonClient.promisifyCall('ListProfiles', { username });
    const profiles = (profilesResponse.profiles || []).map((p: any) => ({
      id: p.id,
      name: p.name,
      email: p.email,
      active: p.active || false,
    }));

    // Create hash to detect changes
    profilesHash = JSON.stringify(profiles);

    // If profiles haven't changed, don't rebuild the menu
    if (profilesHash === cachedProfiles) {
      return;
    }
    cachedProfiles = profilesHash;

    profileMenuItems = profiles.map((profile: any) => ({
      label: `${profile.name}${profile.email ? ` (${profile.email})` : ''}`,
      type: 'radio' as const,
      checked: profile.active,
      click: async () => {
        if (!profile.active) {
          try {
            await daemonClient.switchProfile(profile.id);
          } catch (error) {
            console.error('Failed to switch profile:', error);
          }
        }
      },
    }));
  } catch (error) {
    console.error('Failed to load profiles for menu:', error);
    profileMenuItems = [{
      label: 'Manage Profiles...',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
          mainWindow.webContents.send('navigate', '/profiles');
        } else {
          createWindow();
        }
      },
    }];
  }

  // Add manage profiles option
  if (profileMenuItems.length > 0) {
    profileMenuItems.push({ type: 'separator' });
  }
  profileMenuItems.push({
    label: 'Manage Profiles...',
    click: () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
        mainWindow.webContents.send('navigate', '/profiles');
      } else {
        createWindow();
      }
    },
  });

  const contextMenu = Menu.buildFromTemplate([
    {
      label: connected ? 'Connected' : 'Disconnected',
      enabled: false,
    },
    { type: 'separator' },
    {
      label: connected ? 'Disconnect' : 'Connect',
      click: async () => {
        try {
          if (connected) {
            await daemonClient.down();
          } else {
            await daemonClient.up();
          }
        } catch (error) {
          console.error('Failed to toggle connection:', error);
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Show Dashboard',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        } else {
          createWindow();
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Settings',
      submenu: [
        {
          label: 'Allow SSH',
          type: 'checkbox',
          checked: false,
          click: async (menuItem) => {
            try {
              await daemonClient.updateConfig({ serverSSHAllowed: menuItem.checked });
            } catch (error) {
              console.error('Failed to update SSH setting:', error);
            }
          },
        },
        {
          label: 'Connect on Startup',
          type: 'checkbox',
          checked: false,
          click: async (menuItem) => {
            try {
              await daemonClient.updateConfig({ autoConnect: menuItem.checked });
            } catch (error) {
              console.error('Failed to update auto-connect:', error);
            }
          },
        },
        {
          label: 'Enable Quantum-Resistance (Rosenpass)',
          type: 'checkbox',
          checked: false,
          click: async (menuItem) => {
            try {
              await daemonClient.updateConfig({ rosenpassEnabled: menuItem.checked });
            } catch (error) {
              console.error('Failed to update Rosenpass:', error);
            }
          },
        },
        {
          label: 'Enable Lazy Connections',
          type: 'checkbox',
          checked: false,
          click: async (menuItem) => {
            try {
              await daemonClient.updateConfig({ lazyConnectionEnabled: menuItem.checked });
            } catch (error) {
              console.error('Failed to update lazy connection:', error);
            }
          },
        },
        {
          label: 'Block Inbound Connections',
          type: 'checkbox',
          checked: false,
          click: async (menuItem) => {
            try {
              await daemonClient.updateConfig({ blockInbound: menuItem.checked });
            } catch (error) {
              console.error('Failed to update block inbound:', error);
            }
          },
        },
        { type: 'separator' },
        {
          label: 'Advanced Settings...',
          click: () => {
            if (mainWindow) {
              mainWindow.show();
              mainWindow.focus();
              mainWindow.webContents.send('navigate', '/settings');
            } else {
              createWindow();
            }
          },
        },
      ],
    },
    {
      label: 'Networks',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
          mainWindow.webContents.send('navigate', '/networks');
        } else {
          createWindow();
        }
      },
    },
    {
      label: 'Profiles',
      submenu: profileMenuItems,
    },
    { type: 'separator' },
    {
      label: 'Create Debug Bundle',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
          mainWindow.webContents.send('navigate', '/debug');
        } else {
          createWindow();
        }
      },
    },
    { type: 'separator' },
    {
      label: 'About',
      submenu: [
        {
          label: 'GitHub',
          click: () => {
            require('electron').shell.openExternal('https://github.com/netbirdio/netbird');
          },
        },
        {
          label: 'Version: 0.1.0',
          enabled: false,
        },
      ],
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
}

// App lifecycle
app.whenReady().then(async () => {
  // Initialize gRPC client
  daemonClient = new DaemonClient(DAEMON_ADDR);

  // Create tray
  await createTray();

  // Create window
  await createWindow();

  // Start status polling
  startStatusPolling();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // Don't quit on window close - run in background
  if (process.platform !== 'darwin') {
    // Keep running
  }
});

app.on('before-quit', () => {
  isQuitting = true;
});

// Status polling
function startStatusPolling() {
  setInterval(async () => {
    try {
      const status = await daemonClient.getStatus();
      const connected = status === 'Connected';

      // Update tray icon
      const iconName = connected ? 'tray-icon-connected' : 'tray-icon-disconnected';
      const iconPath = path.join(__dirname, `../../assets/${iconName}.png`);
      const icon = nativeImage.createFromPath(iconPath);
      tray?.setImage(icon.resize({ width: 22, height: 22 }));
      tray?.setToolTip(`NetBird - ${status}`);

      // Update tray menu
      updateTrayMenu(connected);

      // Send status to renderer
      mainWindow?.webContents.send('status-update', { status, connected });
    } catch (error) {
      console.error('Status poll error:', error);
    }
  }, 2000);
}

// IPC handlers
ipcMain.handle('daemon:status', async () => {
  try {
    return await daemonClient.getStatus();
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:status\':', error);
    throw new Error(error.message || error.details || 'Failed to get status');
  }
});

ipcMain.handle('daemon:getFullStatus', async () => {
  try {
    return await daemonClient.getFullStatus();
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:getFullStatus\':', error);
    throw new Error(error.message || error.details || 'Failed to get full status');
  }
});

ipcMain.handle('daemon:up', async () => {
  try {
    return await daemonClient.up();
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:up\':', error);
    throw new Error(error.details || error.message || 'Failed to connect');
  }
});

ipcMain.handle('daemon:down', async () => {
  try {
    return await daemonClient.down();
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:down\':', error);
    throw new Error(error.details || error.message || 'Failed to disconnect');
  }
});

ipcMain.handle('daemon:getConfig', async () => {
  try {
    return await daemonClient.getConfig();
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:getConfig\':', error);
    throw new Error(error.details || error.message || 'Failed to get config');
  }
});

ipcMain.handle('daemon:updateConfig', async (_, config) => {
  try {
    return await daemonClient.updateConfig(config);
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:updateConfig\':', error);
    throw new Error(error.details || error.message || 'Failed to update config');
  }
});

ipcMain.handle('daemon:listNetworks', async () => {
  return await daemonClient.listNetworks();
});

ipcMain.handle('daemon:selectNetworks', async (_, networkIds: string[]) => {
  return await daemonClient.selectNetworks(networkIds);
});

ipcMain.handle('daemon:deselectNetworks', async (_, networkIds: string[]) => {
  return await daemonClient.deselectNetworks(networkIds);
});

ipcMain.handle('daemon:listProfiles', async () => {
  return await daemonClient.listProfiles();
});

ipcMain.handle('daemon:getActiveProfile', async () => {
  return await daemonClient.getActiveProfile();
});

ipcMain.handle('daemon:switchProfile', async (_, profileId: string) => {
  return await daemonClient.switchProfile(profileId);
});

ipcMain.handle('daemon:addProfile', async (_, profileName: string) => {
  return await daemonClient.addProfile(profileName);
});

ipcMain.handle('daemon:removeProfile', async (_, profileId: string) => {
  return await daemonClient.removeProfile(profileId);
});

ipcMain.handle('daemon:logout', async () => {
  try {
    return await daemonClient.logout();
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:logout\':', error);
    throw new Error(error.details || error.message || 'Failed to logout');
  }
});

ipcMain.handle('daemon:login', async (_, setupKey?: string) => {
  try {
    return await daemonClient.login(setupKey);
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:login\':', error);
    throw new Error(error.details || error.message || 'Failed to initiate login');
  }
});

ipcMain.handle('daemon:waitSSOLogin', async (_, userCode: string) => {
  try {
    return await daemonClient.waitSSOLogin(userCode);
  } catch (error: any) {
    console.error('Error occurred in handler for \'daemon:waitSSOLogin\':', error);
    throw new Error(error.details || error.message || 'Failed to wait for SSO login');
  }
});

ipcMain.handle('shell:openExternal', async (_, url: string) => {
  try {
    const { shell } = require('electron');
    await shell.openExternal(url);
    return true;
  } catch (error: any) {
    console.error('Error occurred in handler for \'shell:openExternal\':', error);
    throw new Error(error.message || 'Failed to open URL');
  }
});

ipcMain.handle('fs:getActiveProfile', async () => {
  const profileName = readActiveProfileFromFS();
  if (!profileName) {
    return null;
  }

  const profileState = readProfileState(profileName);
  return {
    id: profileName,
    name: profileName,
    email: profileState?.email || '',
    active: true,
  };
});

ipcMain.handle('fs:setActiveProfile', async (_, profileName: string) => {
  try {
    const configDir = getNetBirdConfigDir();

    // Create config directory if it doesn't exist
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    const activeProfilePath = path.join(configDir, 'active_profile.txt');
    fs.writeFileSync(activeProfilePath, profileName, 'utf-8');

    return true;
  } catch (error) {
    console.error('Error writing active profile to filesystem:', error);
    throw error;
  }
});
