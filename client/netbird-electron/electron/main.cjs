const { app, BrowserWindow, ipcMain, Tray, Menu, screen, shell, dialog } = require('electron');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const { DaemonClient } = require('./grpc-client.cjs');

const execPromise = util.promisify(exec);

// Daemon address - Unix socket on Linux/BSD/macOS, TCP on Windows
const DAEMON_ADDR = process.platform === 'win32'
  ? 'localhost:41731'
  : 'unix:///var/run/netbird.sock';

let mainWindow = null;
let tray = null;
let daemonClient = null;
let daemonVersion = '0.0.0';

// Parse command line arguments for expert mode
const expertMode = process.argv.includes('--expert-mode') || process.argv.includes('--expert');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 520,
    height: 800,
    resizable: false,
    title: 'NetBird',
    backgroundColor: '#1a1a1a',
    autoHideMenuBar: true,
    frame: true,
    show: false, // Don't show initially
    skipTaskbar: true, // Hide from taskbar
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  // Load the app
  if (process.env.NODE_ENV === 'development' || !app.isPackaged) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools(); // Temporarily enabled for debugging
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  // Hide window when it loses focus
  mainWindow.on('blur', () => {
    if (!mainWindow.webContents.isDevToolsOpened()) {
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

let connectionState = 'disconnected'; // 'disconnected', 'connecting', 'connected', 'disconnecting'
let pulseState = false; // For pulsating animation
let pulseInterval = null;

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'netbird-systemtray-disconnected-white-monochrome.png');
  tray = new Tray(iconPath);

  updateTrayMenu();

  tray.setToolTip('NetBird - Disconnected');

  tray.on('click', () => {
    toggleWindow();
  });
}

function getStatusLabel() {
  let indicator = '⚪'; // Gray circle
  let statusText = 'Disconnected';

  switch (connectionState) {
    case 'disconnected':
      indicator = '⚪';
      statusText = 'Disconnected';
      break;
    case 'connecting':
      indicator = pulseState ? '🟢' : '⚪';
      statusText = 'Connecting...';
      break;
    case 'connected':
      indicator = '🟢';
      statusText = 'Connected';
      break;
    case 'disconnecting':
      indicator = pulseState ? '🟢' : '⚪';
      statusText = 'Disconnecting...';
      break;
  }

  return `${indicator}  ${statusText}`;
}

function startPulseAnimation() {
  if (pulseInterval) {
    clearInterval(pulseInterval);
  }

  pulseInterval = setInterval(() => {
    pulseState = !pulseState;
    updateTrayMenu();
  }, 500); // Pulse every 500ms
}

function stopPulseAnimation() {
  if (pulseInterval) {
    clearInterval(pulseInterval);
    pulseInterval = null;
  }
  pulseState = false;
}

function setConnectionState(state) {
  connectionState = state;

  // Start/stop pulse animation based on state
  if (state === 'connecting' || state === 'disconnecting') {
    startPulseAnimation();
  } else {
    stopPulseAnimation();
  }

  updateTrayMenu();
  updateTrayIcon();
}

async function updateTrayMenu() {
  // Fetch version from daemon
  try {
    const statusInfo = await daemonClient.getStatus();
    if (statusInfo.version) {
      daemonVersion = statusInfo.version;
    }
  } catch (error) {
    console.error('Failed to get version:', error);
  }

  const connectDisconnectIcon = connectionState === 'connected' || connectionState === 'disconnecting'
    ? path.join(__dirname, 'assets', 'power-off-icon.png')
    : path.join(__dirname, 'assets', 'power-icon.png');

  const connectDisconnectLabel = connectionState === 'connected' || connectionState === 'disconnecting'
    ? 'Disconnect'
    : 'Connect';

  const menuTemplate = [
    {
      label: getStatusLabel(),
      enabled: false
    },
    { type: 'separator' },
    {
      label: connectDisconnectLabel,
      icon: connectDisconnectIcon,
      enabled: connectionState === 'disconnected' || connectionState === 'connected',
      click: async () => {
        if (connectionState === 'connected') {
          setConnectionState('disconnecting');
          try {
            await daemonClient.down();
            setConnectionState('disconnected');
          } catch (error) {
            console.error('Disconnect error:', error);
            setConnectionState('connected');
          }
        } else if (connectionState === 'disconnected') {
          setConnectionState('connecting');
          try {
            // Step 1: Call login to check if SSO is needed
            console.log('[Tray] Calling login...');
            const loginResp = await daemonClient.login();
            console.log('[Tray] Login response:', loginResp);

            // Step 2: If SSO login is needed, open browser and wait
            if (loginResp.needsSSOLogin) {
              console.log('[Tray] SSO login required, opening browser...');

              // Open the verification URL in the default browser
              if (loginResp.verificationURIComplete) {
                await shell.openExternal(loginResp.verificationURIComplete);
                console.log('[Tray] Opened URL:', loginResp.verificationURIComplete);
              }

              // Wait for user to complete login in browser
              console.log('[Tray] Waiting for SSO login completion...');
              const waitResp = await daemonClient.waitSSOLogin(loginResp.userCode);
              console.log('[Tray] SSO login completed, email:', waitResp.email);
            }

            // Step 3: Call Up to connect
            console.log('[Tray] Calling Up to connect...');
            await daemonClient.up();
            console.log('[Tray] Connected successfully');

            setConnectionState('connected');
          } catch (error) {
            console.error('Connect error:', error);
            setConnectionState('disconnected');
          }
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Show',
      icon: path.join(__dirname, 'assets', 'netbird-systemtray-disconnected-white-monochrome.png'),
      click: () => {
        showWindow();
      }
    }
  ];

  // Add expert mode menu items
  if (expertMode) {
    menuTemplate.push({ type: 'separator' });

    // Profiles submenu - load from daemon
    let profiles = [];
    try {
      profiles = await daemonClient.listProfiles();
    } catch (error) {
      console.error('Failed to load profiles:', error);
    }

    const profilesSubmenu = profiles.map(profile => ({
      label: profile.email ? `${profile.name} (${profile.email})` : profile.name,
      type: 'radio',
      checked: profile.active,
      click: async () => {
        try {
          await daemonClient.switchProfile(profile.name);
          updateTrayMenu(); // Refresh menu after profile switch
        } catch (error) {
          console.error('Failed to switch profile:', error);
        }
      }
    }));

    profilesSubmenu.push({ type: 'separator' });
    profilesSubmenu.push({
      label: 'Add New Profile...',
      click: () => {
        console.log('Add new profile - TODO: implement dialog');
        // TODO: Show dialog to add new profile
      }
    });

    menuTemplate.push({
      label: 'Profiles',
      icon: path.join(__dirname, 'assets', 'profiles-icon.png'),
      submenu: profilesSubmenu
    });

    // Settings submenu - load from daemon
    let config = {};
    try {
      config = await daemonClient.getConfig();
    } catch (error) {
      console.error('Failed to load config:', error);
      // Use defaults if loading fails
      config = {
        autoConnect: false,
        networkMonitor: true,
        disableDns: false,
        blockLanAccess: false,
      };
    }

    menuTemplate.push({
      label: 'Settings',
      icon: path.join(__dirname, 'assets', 'settings-icon.png'),
      submenu: [
        {
          label: 'Auto Connect',
          type: 'checkbox',
          checked: config.autoConnect || false,
          click: async (menuItem) => {
            console.log('Auto Connect:', menuItem.checked);
            try {
              await daemonClient.updateConfig({ autoConnect: menuItem.checked });
            } catch (error) {
              console.error('Failed to update autoConnect:', error);
            }
          }
        },
        {
          label: 'Network Monitor',
          type: 'checkbox',
          checked: config.networkMonitor !== undefined ? config.networkMonitor : true,
          click: async (menuItem) => {
            console.log('Network Monitor:', menuItem.checked);
            try {
              await daemonClient.updateConfig({ networkMonitor: menuItem.checked });
            } catch (error) {
              console.error('Failed to update networkMonitor:', error);
            }
          }
        },
        {
          label: 'Disable DNS',
          type: 'checkbox',
          checked: config.disableDns || false,
          click: async (menuItem) => {
            console.log('Disable DNS:', menuItem.checked);
            try {
              await daemonClient.updateConfig({ disableDns: menuItem.checked });
            } catch (error) {
              console.error('Failed to update disableDns:', error);
            }
          }
        },
        {
          label: 'Block LAN Access',
          type: 'checkbox',
          checked: config.blockLanAccess || false,
          click: async (menuItem) => {
            console.log('Block LAN Access:', menuItem.checked);
            try {
              await daemonClient.updateConfig({ blockLanAccess: menuItem.checked });
            } catch (error) {
              console.error('Failed to update blockLanAccess:', error);
            }
          }
        }
      ]
    });

    // Networks button
    menuTemplate.push({
      label: 'Networks',
      icon: path.join(__dirname, 'assets', 'networks-icon.png'),
      click: () => {
        showWindow('networks');
      }
    });

    // Exit Nodes button
    menuTemplate.push({
      label: 'Exit Nodes',
      icon: path.join(__dirname, 'assets', 'exit-node-icon.png'),
      click: () => {
        showWindow('networks'); // Assuming exit nodes is part of networks tab
      }
    });
  }

  // Add Debug (available in both modes)
  menuTemplate.push({ type: 'separator' });
  menuTemplate.push({
    label: 'Debug',
    icon: path.join(__dirname, 'assets', 'debug-icon.png'),
    click: () => {
      showWindow('debug');
    }
  });

  // Add About and Quit
  menuTemplate.push({ type: 'separator' });
  menuTemplate.push({
    label: 'About',
    icon: path.join(__dirname, 'assets', 'info-icon.png'),
    submenu: [
      {
        label: `Version: ${daemonVersion}`,
        icon: path.join(__dirname, 'assets', 'version-icon.png'),
        enabled: false
      },
      {
        label: 'Check for Updates',
        icon: path.join(__dirname, 'assets', 'refresh-icon.png'),
        click: () => {
          // TODO: Implement update check
          console.log('Checking for updates...');
        }
      }
    ]
  });
  menuTemplate.push({ type: 'separator' });
  menuTemplate.push({
    label: 'Quit',
    icon: path.join(__dirname, 'assets', 'quit-icon.png'),
    click: () => {
      app.quit();
    }
  });

  const contextMenu = Menu.buildFromTemplate(menuTemplate);
  tray.setContextMenu(contextMenu);
}

function updateTrayIcon() {
  let iconName = 'netbird-systemtray-disconnected-white-monochrome.png';
  let tooltip = 'NetBird - Disconnected';

  switch (connectionState) {
    case 'disconnected':
      iconName = 'netbird-systemtray-disconnected-white-monochrome.png';
      tooltip = 'NetBird - Disconnected';
      break;
    case 'connecting':
      iconName = 'netbird-systemtray-connecting-white-monochrome.png';
      tooltip = 'NetBird - Connecting...';
      break;
    case 'connected':
      iconName = 'netbird-systemtray-connected-white-monochrome.png';
      tooltip = 'NetBird - Connected';
      break;
    case 'disconnecting':
      iconName = 'netbird-systemtray-connecting-white-monochrome.png';
      tooltip = 'NetBird - Disconnecting...';
      break;
  }

  const iconPath = path.join(__dirname, 'assets', iconName);
  tray.setImage(iconPath);
  tray.setToolTip(tooltip);
}

async function syncConnectionState() {
  try {
    const statusInfo = await daemonClient.getStatus();
    const daemonStatus = statusInfo.status || 'Disconnected';

    // Map daemon status to our connection state
    let newState = 'disconnected';
    if (daemonStatus === 'Connected') {
      newState = 'connected';
    } else if (daemonStatus === 'Connecting') {
      newState = 'connecting';
    } else {
      newState = 'disconnected';
    }

    // Only update if state changed to avoid unnecessary menu rebuilds
    if (newState !== connectionState) {
      console.log(`[Tray] Connection state changed: ${connectionState} -> ${newState}`);
      setConnectionState(newState);
    }
  } catch (error) {
    console.error('[Tray] Failed to sync connection state:', error);
    // On error, assume disconnected
    if (connectionState !== 'disconnected') {
      setConnectionState('disconnected');
    }
  }
}

function toggleWindow() {
  if (mainWindow.isVisible()) {
    mainWindow.hide();
  } else {
    showWindow();
  }
}

function showWindow(page) {
  const windowBounds = mainWindow.getBounds();
  const trayBounds = tray.getBounds();

  // Calculate position (center horizontally under tray icon)
  const x = Math.round(trayBounds.x + (trayBounds.width / 2) - (windowBounds.width / 2));
  const y = Math.round(trayBounds.y + trayBounds.height + 4);

  mainWindow.setPosition(x, y, false);
  mainWindow.show();
  mainWindow.focus();

  // Send page navigation message to renderer if page is specified
  if (page) {
    mainWindow.webContents.send('navigate-to-page', page);
  }
}

app.whenReady().then(async () => {
  // Initialize gRPC client
  daemonClient = new DaemonClient(DAEMON_ADDR);

  createWindow();
  createTray();

  // Initialize connection state from daemon
  await syncConnectionState();

  // Poll daemon status every 3 seconds to keep tray updated
  setInterval(async () => {
    await syncConnectionState();
  }, 3000);
});

app.on('window-all-closed', (e) => {
  // Prevent app from quitting - tray app should stay running
  e.preventDefault();
});

// IPC Handlers for NetBird daemon communication via gRPC
ipcMain.handle('netbird:connect', async () => {
  try {
    // Check if already connected
    const status = await daemonClient.getStatus();
    if (status.status === 'Connected') {
      console.log('Already connected');
      return { success: true };
    }

    // Step 1: Call login to check if SSO is needed
    console.log('Calling login...');
    const loginResp = await daemonClient.login();
    console.log('Login response:', loginResp);

    // Step 2: If SSO login is needed, open browser and wait
    if (loginResp.needsSSOLogin) {
      console.log('SSO login required, opening browser...');

      // Open the verification URL in the default browser
      if (loginResp.verificationURIComplete) {
        const { shell } = require('electron');
        await shell.openExternal(loginResp.verificationURIComplete);
        console.log('Opened URL:', loginResp.verificationURIComplete);
      }

      // Wait for user to complete login in browser
      console.log('Waiting for SSO login completion...');
      const waitResp = await daemonClient.waitSSOLogin(loginResp.userCode);
      console.log('SSO login completed, email:', waitResp.email);
    }

    // Step 3: Call Up to connect
    console.log('Calling Up to connect...');
    await daemonClient.up();
    console.log('Connected successfully');

    return { success: true };
  } catch (error) {
    console.error('Connection error:', error);
    throw new Error(error.message || 'Failed to connect');
  }
});

ipcMain.handle('netbird:disconnect', async () => {
  try {
    await daemonClient.down();
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:logout', async () => {
  try {
    await daemonClient.logout();
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:status', async () => {
  try {
    const statusInfo = await daemonClient.getStatus();
    return {
      status: statusInfo.status,
      version: statusInfo.version,
      daemon: 'Connected'
    };
  } catch (error) {
    return {
      status: 'Disconnected',
      version: '0.0.0',
      daemon: 'Disconnected'
    };
  }
});

ipcMain.handle('netbird:get-config', async () => {
  try {
    return await daemonClient.getConfig();
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:update-config', async (event, config) => {
  try {
    await daemonClient.updateConfig(config);
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:get-networks', async () => {
  try {
    // TODO: Implement networks retrieval via gRPC
    return [];
  } catch (error) {
    return [];
  }
});

ipcMain.handle('netbird:toggle-network', async (event, networkId) => {
  try {
    // TODO: Implement network toggle via gRPC
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:get-profiles', async () => {
  try {
    return await daemonClient.listProfiles();
  } catch (error) {
    console.error('get-profiles error:', error);
    return [];
  }
});

ipcMain.handle('netbird:switch-profile', async (event, profileId) => {
  try {
    await daemonClient.switchProfile(profileId);
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:delete-profile', async (event, profileId) => {
  try {
    await daemonClient.removeProfile(profileId);
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:add-profile', async (event, name) => {
  try {
    await daemonClient.addProfile(name);
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:remove-profile', async (event, profileId) => {
  try {
    await daemonClient.removeProfile(profileId);
    return { success: true };
  } catch (error) {
    throw new Error(error.message);
  }
});

ipcMain.handle('netbird:get-peers', async () => {
  try {
    return await daemonClient.getPeers();
  } catch (error) {
    console.error('get-peers error:', error);
    return [];
  }
});

ipcMain.handle('netbird:get-local-peer', async () => {
  try {
    return await daemonClient.getLocalPeer();
  } catch (error) {
    console.error('get-local-peer error:', error);
    return null;
  }
});

ipcMain.handle('netbird:get-expert-mode', async () => {
  return expertMode;
});
