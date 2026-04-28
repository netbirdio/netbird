import 'dart:async';
import 'dart:io';

import 'package:local_notifier/local_notifier.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'daemon_client.dart';
import 'models.dart';
import 'platform.dart';

const uiVersion = '0.1.0';
const _githubUrl = 'https://github.com/netbirdio/netbird';
const _downloadUrl = 'https://netbird.io/download/';

class TabIndex {
  static const status = 0;
  static const networks = 1;
  static const profiles = 2;
  static const settings = 3;
  static const debug = 4;
}

/// Owns native desktop integration: window lifecycle (hide on close), system
/// tray icon and menu, and OS-level notifications driven by daemon events.
class DesktopIntegration with TrayListener, WindowListener {
  DesktopIntegration({required this.client});

  final DaemonClient client;
  final _tabRequests = StreamController<int>.broadcast();

  StreamSubscription<ClientSnapshot>? _snapshotSub;
  StreamSubscription<SystemNotification>? _eventSub;
  ClientSnapshot? _lastSnapshot;
  String? _lastMenuKey;
  bool _disposed = false;
  bool _settingsBusy = false;

  Stream<int> get tabRequests => _tabRequests.stream;

  static const _trayMenuConnect = 'connect';
  static const _trayMenuDisconnect = 'disconnect';
  static const _trayMenuShow = 'show';
  static const _trayMenuQuit = 'quit';
  static const _trayMenuAllowSSH = 'settings.allow_ssh';
  static const _trayMenuAutoConnect = 'settings.auto_connect';
  static const _trayMenuQuantum = 'settings.quantum';
  static const _trayMenuLazy = 'settings.lazy';
  static const _trayMenuBlockInbound = 'settings.block_inbound';
  static const _trayMenuNotifications = 'settings.notifications';
  static const _trayMenuAdvancedSettings = 'open.settings';
  static const _trayMenuDebugBundle = 'open.debug';
  static const _trayMenuNetworks = 'open.networks';
  static const _trayMenuManageProfiles = 'open.profiles';
  static const _trayMenuLogout = 'profile.logout';
  static const _trayMenuGithub = 'about.github';
  static const _trayMenuDownload = 'about.download';
  static const _profileSwitchPrefix = 'profile.switch:';

  Future<void> initialize() async {
    await localNotifier.setup(appName: 'NetBird');
    await windowManager.setPreventClose(true);
    windowManager.addListener(this);
    trayManager.addListener(this);

    await _applyTrayIcon(ConnectionStatus.disconnected);
    await trayManager.setToolTip('NetBird');
    await _refreshTrayMenu(null);

    _snapshotSub = client.watchSnapshot().listen(_onSnapshot);
    _eventSub = client.watchEvents().listen(_onEvent);
  }

  Future<void> dispose() async {
    if (_disposed) {
      return;
    }
    _disposed = true;
    await _snapshotSub?.cancel();
    await _eventSub?.cancel();
    await _tabRequests.close();
    windowManager.removeListener(this);
    trayManager.removeListener(this);
    await trayManager.destroy();
  }

  @override
  void onWindowClose() {
    unawaited(_handleWindowClose());
  }

  Future<void> _handleWindowClose() async {
    final prevent = await windowManager.isPreventClose();
    if (prevent) {
      await windowManager.hide();
    }
  }

  @override
  void onTrayIconMouseDown() {
    if (Platform.isMacOS) {
      unawaited(trayManager.popUpContextMenu());
    } else {
      unawaited(_showWindow());
    }
  }

  @override
  void onTrayIconRightMouseDown() {
    unawaited(trayManager.popUpContextMenu());
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    final key = menuItem.key;
    if (key == null) {
      return;
    }
    if (key.startsWith(_profileSwitchPrefix)) {
      final name = key.substring(_profileSwitchPrefix.length);
      unawaited(_switchProfile(name));
      return;
    }
    switch (key) {
      case _trayMenuConnect:
        unawaited(client.connect());
      case _trayMenuDisconnect:
        unawaited(client.disconnect());
      case _trayMenuShow:
        unawaited(_showWindow());
      case _trayMenuQuit:
        unawaited(_quit());
      case _trayMenuAllowSSH:
        unawaited(_toggleSetting((s) => s.copyWith(allowSsh: !s.allowSsh)));
      case _trayMenuAutoConnect:
        unawaited(
          _toggleSetting((s) => s.copyWith(autoConnect: !s.autoConnect)),
        );
      case _trayMenuQuantum:
        unawaited(
          _toggleSetting(
            (s) => s.copyWith(quantumResistance: !s.quantumResistance),
          ),
        );
      case _trayMenuLazy:
        unawaited(
          _toggleSetting(
            (s) => s.copyWith(lazyConnection: !s.lazyConnection),
          ),
        );
      case _trayMenuBlockInbound:
        unawaited(
          _toggleSetting(
            (s) => s.copyWith(blockInbound: !s.blockInbound),
          ),
        );
      case _trayMenuNotifications:
        unawaited(
          _toggleSetting(
            (s) => s.copyWith(notifications: !s.notifications),
          ),
        );
      case _trayMenuAdvancedSettings:
        unawaited(_openTab(TabIndex.settings));
      case _trayMenuDebugBundle:
        unawaited(_openTab(TabIndex.debug));
      case _trayMenuNetworks:
        unawaited(_openTab(TabIndex.networks));
      case _trayMenuManageProfiles:
        unawaited(_openTab(TabIndex.profiles));
      case _trayMenuLogout:
        unawaited(client.logoutActive());
      case _trayMenuGithub:
        unawaited(openExternalUrl(_githubUrl));
      case _trayMenuDownload:
        unawaited(openExternalUrl(_downloadUrl));
    }
  }

  Future<void> _openTab(int index) async {
    if (!_tabRequests.isClosed) {
      _tabRequests.add(index);
    }
    await _showWindow();
  }

  Future<void> _toggleSetting(
    ClientSettings Function(ClientSettings) mutate,
  ) async {
    if (_settingsBusy) {
      return;
    }
    final snapshot = _lastSnapshot;
    if (snapshot == null) {
      return;
    }
    _settingsBusy = true;
    try {
      await client.updateSettings(mutate(snapshot.settings));
    } finally {
      _settingsBusy = false;
    }
  }

  Future<void> _switchProfile(String name) async {
    final snapshot = _lastSnapshot;
    if (snapshot == null || snapshot.activeProfile.name == name) {
      return;
    }
    await client.switchProfile(name);
  }

  Future<void> _showWindow() async {
    await windowManager.show();
    await windowManager.focus();
  }

  Future<void> _quit() async {
    await dispose();
    await windowManager.setPreventClose(false);
    await windowManager.destroy();
  }

  void _onSnapshot(ClientSnapshot snapshot) {
    final previous = _lastSnapshot;
    _lastSnapshot = snapshot;
    if (previous == null || previous.status != snapshot.status) {
      unawaited(_applyTrayIcon(snapshot.status));
      unawaited(trayManager.setToolTip('NetBird — ${snapshot.status.label}'));
    }
    unawaited(_refreshTrayMenu(snapshot));
  }

  void _onEvent(SystemNotification event) {
    if (event.userMessage.isEmpty) {
      return;
    }
    final notificationsEnabled =
        _lastSnapshot?.settings.notifications ?? true;
    final critical = event.severity == NotificationSeverity.critical;
    if (!notificationsEnabled && !critical) {
      return;
    }

    final title = '${_severityPrefix(event.severity)} [${event.category.label}]';
    final body = event.id == null
        ? event.userMessage
        : '${event.userMessage} (id: ${event.id})';

    unawaited(
      LocalNotification(title: title, body: body).show(),
    );
  }

  Future<void> _applyTrayIcon(ConnectionStatus status) async {
    final basename = switch (status) {
      ConnectionStatus.connected => 'connected',
      ConnectionStatus.connecting ||
      ConnectionStatus.awaitingLogin => 'connecting',
      ConnectionStatus.error => 'error',
      ConnectionStatus.disconnected => 'disconnected',
    };
    final asset = Platform.isMacOS
        ? 'assets/tray/$basename-macos.png'
        : 'assets/tray/$basename.png';
    await trayManager.setIcon(asset, isTemplate: Platform.isMacOS);
  }

  Future<void> _refreshTrayMenu(ClientSnapshot? snapshot) async {
    final key = _menuKey(snapshot);
    if (key == _lastMenuKey) {
      return;
    }
    _lastMenuKey = key;

    final connected = snapshot?.status == ConnectionStatus.connected;
    final connecting = snapshot?.status == ConnectionStatus.connecting ||
        snapshot?.status == ConnectionStatus.awaitingLogin;

    final statusLabel =
        snapshot?.status.label ?? ConnectionStatus.disconnected.label;
    final settings = snapshot?.settings ?? const ClientSettings();
    final activeName = snapshot?.activeProfile.name ?? 'unknown';
    final email = snapshot?.activeProfile.email;
    final daemonVersion = snapshot?.daemonVersion ?? 'unknown';

    final profileItems = <MenuItem>[];
    final profiles = snapshot?.profiles ?? const <ProfileInfo>[];
    for (final profile in profiles) {
      profileItems.add(
        MenuItem.checkbox(
          key: '$_profileSwitchPrefix${profile.name}',
          label: profile.name,
          checked: profile.active,
        ),
      );
    }
    if (profileItems.isNotEmpty) {
      profileItems.add(MenuItem.separator());
    }
    profileItems
      ..add(MenuItem(key: _trayMenuManageProfiles, label: 'Manage Profiles'))
      ..add(
        MenuItem(
          key: _trayMenuLogout,
          label: 'Deregister',
          disabled: !connected,
        ),
      );

    await trayManager.setContextMenu(
      Menu(
        items: [
          MenuItem(label: statusLabel, disabled: true),
          MenuItem.submenu(
            label: 'Profile: $activeName',
            submenu: Menu(items: profileItems),
          ),
          if (email != null && email.isNotEmpty)
            MenuItem(label: '($email)', disabled: true),
          MenuItem.separator(),
          MenuItem(
            key: _trayMenuConnect,
            label: 'Connect',
            disabled: connected || connecting,
          ),
          MenuItem(
            key: _trayMenuDisconnect,
            label: 'Disconnect',
            disabled: !connected,
          ),
          MenuItem.separator(),
          MenuItem.submenu(
            label: 'Settings',
            submenu: Menu(
              items: [
                MenuItem.checkbox(
                  key: _trayMenuAllowSSH,
                  label: 'Allow SSH',
                  checked: settings.allowSsh,
                ),
                MenuItem.checkbox(
                  key: _trayMenuAutoConnect,
                  label: 'Connect on Startup',
                  checked: settings.autoConnect,
                ),
                MenuItem.checkbox(
                  key: _trayMenuQuantum,
                  label: 'Enable Quantum-Resistance',
                  checked: settings.quantumResistance,
                ),
                MenuItem.checkbox(
                  key: _trayMenuLazy,
                  label: 'Enable Lazy Connections',
                  checked: settings.lazyConnection,
                ),
                MenuItem.checkbox(
                  key: _trayMenuBlockInbound,
                  label: 'Block Inbound Connections',
                  checked: settings.blockInbound,
                ),
                MenuItem.checkbox(
                  key: _trayMenuNotifications,
                  label: 'Notifications',
                  checked: settings.notifications,
                ),
                MenuItem.separator(),
                MenuItem(
                  key: _trayMenuAdvancedSettings,
                  label: 'Advanced Settings',
                ),
                MenuItem(
                  key: _trayMenuDebugBundle,
                  label: 'Create Debug Bundle',
                ),
              ],
            ),
          ),
          MenuItem(key: _trayMenuNetworks, label: 'Networks'),
          MenuItem.separator(),
          MenuItem.submenu(
            label: 'About',
            submenu: Menu(
              items: [
                MenuItem(key: _trayMenuGithub, label: 'GitHub'),
                MenuItem(label: 'GUI: $uiVersion', disabled: true),
                MenuItem(label: 'Daemon: $daemonVersion', disabled: true),
                MenuItem(
                  key: _trayMenuDownload,
                  label: 'Download latest version',
                ),
              ],
            ),
          ),
          MenuItem.separator(),
          MenuItem(key: _trayMenuShow, label: 'Show window'),
          MenuItem(key: _trayMenuQuit, label: 'Quit'),
        ],
      ),
    );
  }

  String _menuKey(ClientSnapshot? snapshot) {
    if (snapshot == null) {
      return 'null';
    }
    final s = snapshot.settings;
    final profiles = snapshot.profiles
        .map((p) => '${p.name}:${p.active}:${p.email ?? ''}')
        .join(',');
    return [
      snapshot.status.name,
      snapshot.activeProfile.name,
      snapshot.activeProfile.email ?? '',
      snapshot.daemonVersion,
      profiles,
      s.allowSsh,
      s.autoConnect,
      s.quantumResistance,
      s.lazyConnection,
      s.blockInbound,
      s.notifications,
    ].join('|');
  }

  String _severityPrefix(NotificationSeverity severity) {
    return switch (severity) {
      NotificationSeverity.critical => 'Critical',
      NotificationSeverity.error => 'Error',
      NotificationSeverity.warning => 'Warning',
      NotificationSeverity.info => 'Info',
    };
  }
}
