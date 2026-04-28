import 'dart:async';
import 'dart:io';

import 'package:grpc/grpc.dart';

import 'generated/daemon.pbgrpc.dart' as daemon;
import 'models.dart';
import 'platform.dart';

const _userAgent = 'netbird-desktop-ui/development';

abstract class DaemonClient {
  String get daemonAddr;

  Stream<ClientSnapshot> watchSnapshot();

  Stream<SystemNotification> watchEvents();

  Stream<UpdateProgressEvent> watchUpdateRequests();

  Future<void> connect();

  Future<void> disconnect();

  Future<void> bringUp();

  Future<void> bringDown();

  Future<DebugBundleResult> debugBundle({
    required bool anonymize,
    required bool systemInfo,
    String? uploadUrl,
  });

  Future<DaemonLogLevel> getLogLevel();

  Future<void> setLogLevel(DaemonLogLevel level);

  Future<void> setSyncResponsePersistence(bool enabled);

  Future<void> startCpuProfile();

  Future<void> stopCpuProfile();

  Future<TriggerUpdateResult> triggerUpdate();

  Future<InstallerResult> getInstallerResult();

  Future<void> updateSettings(ClientSettings updated);

  Future<void> setNetworkSelection(String routeId, bool selected);

  Future<void> setExitNode(String? routeId);

  Future<void> switchProfile(String name);

  Future<void> addProfile(String name);

  Future<void> removeProfile(String name);

  Future<void> logoutActive();

  void dispose();
}

class GrpcDaemonClient implements DaemonClient {
  GrpcDaemonClient({required this.daemonAddr}) {
    _snapshot = ClientSnapshot.initial(daemonAddr);
    _channel = _createChannel(daemonAddr);
    _client = daemon.DaemonServiceClient(_channel);
  }

  @override
  final String daemonAddr;

  final _snapshots = StreamController<ClientSnapshot>.broadcast();
  final _events = StreamController<SystemNotification>.broadcast();
  final _updateRequests = StreamController<UpdateProgressEvent>.broadcast();
  final _refreshInterval = const Duration(seconds: 2);
  final _callTimeout = const Duration(seconds: 5);
  final _ssoLoginTimeout = const Duration(minutes: 5);
  final _installerPollTimeout = const Duration(minutes: 15);

  late final ClientChannel _channel;
  late final daemon.DaemonServiceClient _client;
  late ClientSnapshot _snapshot;

  Timer? _poller;
  StreamSubscription<daemon.SystemEvent>? _eventSubscription;
  var _started = false;

  @override
  Stream<ClientSnapshot> watchSnapshot() {
    _start();
    scheduleMicrotask(_emit);
    return _snapshots.stream;
  }

  @override
  Stream<SystemNotification> watchEvents() {
    _start();
    return _events.stream;
  }

  @override
  Stream<UpdateProgressEvent> watchUpdateRequests() {
    _start();
    return _updateRequests.stream;
  }

  @override
  Future<void> connect() async {
    _setStatus(ConnectionStatus.connecting, clearError: true);
    try {
      await _runLoginFlow();
      await _client.up(
        daemon.UpRequest(username: _username()),
        options: _options(timeout: const Duration(seconds: 30)),
      );
    } catch (error) {
      _snapshot = _snapshot.copyWith(
        status: ConnectionStatus.error,
        errorMessage: _formatError(error),
        clearPendingLogin: true,
      );
      _emit();
      return;
    } finally {
      await _refresh();
    }
  }

  @override
  Future<void> disconnect() async {
    await _runRpc(() async {
      await _client.down(daemon.DownRequest(), options: _options());
    });
  }

  @override
  Future<void> bringUp() async {
    await _client.up(
      daemon.UpRequest(username: _username()),
      options: _options(timeout: const Duration(seconds: 30)),
    );
  }

  @override
  Future<void> bringDown() async {
    await _client.down(
      daemon.DownRequest(),
      options: _options(timeout: const Duration(seconds: 15)),
    );
  }

  @override
  Future<DebugBundleResult> debugBundle({
    required bool anonymize,
    required bool systemInfo,
    String? uploadUrl,
  }) async {
    final request = daemon.DebugBundleRequest(
      anonymize: anonymize,
      systemInfo: systemInfo,
      uploadURL: uploadUrl ?? '',
    );
    final response = await _client.debugBundle(
      request,
      options: _options(timeout: const Duration(minutes: 2)),
    );
    return DebugBundleResult(
      path: response.path,
      uploadedKey: response.uploadedKey,
      uploadFailureReason: response.uploadFailureReason,
    );
  }

  @override
  Future<DaemonLogLevel> getLogLevel() async {
    final response = await _client.getLogLevel(
      daemon.GetLogLevelRequest(),
      options: _options(),
    );
    return _mapLogLevelFromProto(response.level);
  }

  @override
  Future<void> setLogLevel(DaemonLogLevel level) async {
    await _client.setLogLevel(
      daemon.SetLogLevelRequest(level: _mapLogLevelToProto(level)),
      options: _options(),
    );
  }

  @override
  Future<void> setSyncResponsePersistence(bool enabled) async {
    await _client.setSyncResponsePersistence(
      daemon.SetSyncResponsePersistenceRequest(enabled: enabled),
      options: _options(),
    );
  }

  @override
  Future<void> startCpuProfile() async {
    await _client.startCPUProfile(
      daemon.StartCPUProfileRequest(),
      options: _options(),
    );
  }

  @override
  Future<void> stopCpuProfile() async {
    await _client.stopCPUProfile(
      daemon.StopCPUProfileRequest(),
      options: _options(),
    );
  }

  @override
  Future<TriggerUpdateResult> triggerUpdate() async {
    final response = await _client.triggerUpdate(
      daemon.TriggerUpdateRequest(),
      options: _options(timeout: const Duration(seconds: 30)),
    );
    return TriggerUpdateResult(
      success: response.success,
      errorMessage: response.errorMsg,
    );
  }

  @override
  Future<InstallerResult> getInstallerResult() async {
    final response = await _client.getInstallerResult(
      daemon.InstallerResultRequest(),
      options: _options(timeout: _installerPollTimeout),
    );
    return InstallerResult(
      success: response.success,
      errorMessage: response.errorMsg,
    );
  }

  @override
  Future<void> updateSettings(ClientSettings updated) async {
    await _runRpc(() async {
      final activeProfile = _snapshot.activeProfile.name;
      await _client.setConfig(
        daemon.SetConfigRequest(
          username: _username(),
          profileName: activeProfile,
          managementUrl: updated.managementUrl,
          rosenpassEnabled: updated.quantumResistance,
          serverSSHAllowed: updated.allowSsh,
          disableAutoConnect: !updated.autoConnect,
          disableNotifications: !updated.notifications,
          lazyConnectionEnabled: updated.lazyConnection,
          blockInbound: updated.blockInbound,
        ),
        options: _options(timeout: const Duration(seconds: 10)),
      );
    });
  }

  @override
  Future<void> setNetworkSelection(String routeId, bool selected) async {
    await _runRpc(() async {
      final request = daemon.SelectNetworksRequest(networkIDs: [routeId]);
      if (selected) {
        await _client.selectNetworks(request, options: _options());
      } else {
        await _client.deselectNetworks(request, options: _options());
      }
    });
  }

  @override
  Future<void> setExitNode(String? routeId) async {
    await _runRpc(() async {
      final exitNodeIds = _snapshot.networks
          .where((route) => route.isExitNode)
          .map((route) => route.id)
          .toList();
      if (exitNodeIds.isNotEmpty) {
        await _client.deselectNetworks(
          daemon.SelectNetworksRequest(networkIDs: exitNodeIds),
          options: _options(),
        );
      }
      if (routeId != null) {
        await _client.selectNetworks(
          daemon.SelectNetworksRequest(networkIDs: [routeId]),
          options: _options(),
        );
      }
    });
  }

  @override
  Future<void> switchProfile(String name) async {
    await _runRpc(() async {
      await _client.switchProfile(
        daemon.SwitchProfileRequest(profileName: name, username: _username()),
        options: _options(),
      );
    });
  }

  @override
  Future<void> addProfile(String name) async {
    await _runRpc(() async {
      await _client.addProfile(
        daemon.AddProfileRequest(profileName: name, username: _username()),
        options: _options(),
      );
    });
  }

  @override
  Future<void> removeProfile(String name) async {
    await _runRpc(() async {
      await _client.removeProfile(
        daemon.RemoveProfileRequest(profileName: name, username: _username()),
        options: _options(),
      );
    });
  }

  @override
  Future<void> logoutActive() async {
    await _runRpc(() async {
      final active = _snapshot.activeProfile.name;
      await _client.logout(
        daemon.LogoutRequest(profileName: active, username: _username()),
        options: _options(timeout: const Duration(seconds: 15)),
      );
    });
  }

  @override
  void dispose() {
    _poller?.cancel();
    unawaited(_eventSubscription?.cancel() ?? Future<void>.value());
    _events.close();
    _updateRequests.close();
    _snapshots.close();
    unawaited(_channel.shutdown());
  }

  void _start() {
    if (_started) {
      return;
    }
    _started = true;
    unawaited(_refresh());
    _poller = Timer.periodic(_refreshInterval, (_) {
      unawaited(_refresh());
    });
    _eventSubscription = _client
        .subscribeEvents(daemon.SubscribeRequest(), options: _options())
        .listen(
          (event) {
            _checkUpdateMetadata(event);
            final notification = _mapSystemEvent(event);
            if (notification != null && !_events.isClosed) {
              _events.add(notification);
            }
            unawaited(_refresh());
          },
          onError: (_) {},
        );
  }

  DaemonLogLevel _mapLogLevelFromProto(daemon.LogLevel level) {
    return switch (level) {
      daemon.LogLevel.PANIC => DaemonLogLevel.panic,
      daemon.LogLevel.FATAL => DaemonLogLevel.fatal,
      daemon.LogLevel.ERROR => DaemonLogLevel.error,
      daemon.LogLevel.WARN => DaemonLogLevel.warn,
      daemon.LogLevel.INFO => DaemonLogLevel.info,
      daemon.LogLevel.DEBUG => DaemonLogLevel.debug,
      daemon.LogLevel.TRACE => DaemonLogLevel.trace,
      _ => DaemonLogLevel.unknown,
    };
  }

  daemon.LogLevel _mapLogLevelToProto(DaemonLogLevel level) {
    return switch (level) {
      DaemonLogLevel.panic => daemon.LogLevel.PANIC,
      DaemonLogLevel.fatal => daemon.LogLevel.FATAL,
      DaemonLogLevel.error => daemon.LogLevel.ERROR,
      DaemonLogLevel.warn => daemon.LogLevel.WARN,
      DaemonLogLevel.info => daemon.LogLevel.INFO,
      DaemonLogLevel.debug => daemon.LogLevel.DEBUG,
      DaemonLogLevel.trace => daemon.LogLevel.TRACE,
      DaemonLogLevel.unknown => daemon.LogLevel.UNKNOWN,
    };
  }

  void _checkUpdateMetadata(daemon.SystemEvent event) {
    final action = event.metadata['progress_window'];
    if (action != 'show') {
      return;
    }
    final version = event.metadata['version'] ?? 'unknown';
    if (!_updateRequests.isClosed) {
      _updateRequests.add(UpdateProgressEvent(version: version));
    }
  }

  SystemNotification? _mapSystemEvent(daemon.SystemEvent event) {
    final severity = switch (event.severity) {
      daemon.SystemEvent_Severity.WARNING => NotificationSeverity.warning,
      daemon.SystemEvent_Severity.ERROR => NotificationSeverity.error,
      daemon.SystemEvent_Severity.CRITICAL => NotificationSeverity.critical,
      _ => NotificationSeverity.info,
    };
    final category = switch (event.category) {
      daemon.SystemEvent_Category.NETWORK => NotificationCategory.network,
      daemon.SystemEvent_Category.DNS => NotificationCategory.dns,
      daemon.SystemEvent_Category.AUTHENTICATION =>
        NotificationCategory.authentication,
      daemon.SystemEvent_Category.CONNECTIVITY =>
        NotificationCategory.connectivity,
      daemon.SystemEvent_Category.SYSTEM => NotificationCategory.system,
      _ => NotificationCategory.system,
    };
    return SystemNotification(
      severity: severity,
      category: category,
      message: event.message,
      userMessage: event.userMessage,
      id: event.metadata['id'],
    );
  }

  Future<void> _runLoginFlow() async {
    final loginResponse = await _client.login(
      daemon.LoginRequest(
        isUnixDesktopClient: Platform.isLinux,
        profileName: _snapshot.activeProfile.name,
        username: _username(),
        hint: _snapshot.activeProfile.email,
      ),
      options: _options(timeout: const Duration(seconds: 30)),
    );

    if (!loginResponse.needsSSOLogin) {
      return;
    }

    _snapshot = _snapshot.copyWith(
      status: ConnectionStatus.awaitingLogin,
      pendingLogin: PendingLogin(
        verificationUri: loginResponse.verificationURIComplete,
        userCode: loginResponse.userCode,
      ),
    );
    _emit();

    if (loginResponse.verificationURIComplete.isNotEmpty) {
      await openExternalUrl(loginResponse.verificationURIComplete);
    }

    await _client.waitSSOLogin(
      daemon.WaitSSOLoginRequest(userCode: loginResponse.userCode),
      options: _options(timeout: _ssoLoginTimeout),
    );

    _snapshot = _snapshot.copyWith(
      status: ConnectionStatus.connecting,
      clearPendingLogin: true,
    );
    _emit();
  }

  Future<void> _runRpc(Future<void> Function() action) async {
    try {
      _snapshot = _snapshot.copyWith(clearError: true);
      _emit();
      await action();
    } catch (error) {
      _snapshot = _snapshot.copyWith(
        status: ConnectionStatus.error,
        errorMessage: _formatError(error),
      );
      _emit();
    } finally {
      await _refresh();
    }
  }

  Future<void> _refresh() async {
    try {
      final status = await _client.status(
        daemon.StatusRequest(),
        options: _options(),
      );

      final activeProfile = await _loadActiveProfile();
      final profiles = await _loadProfiles(activeProfile);
      final networks = await _loadNetworks();
      final settings = await _loadSettings(activeProfile);

      final mappedStatus = _mapStatus(status.status);
      final preserveAwaiting =
          _snapshot.status == ConnectionStatus.awaitingLogin &&
          mappedStatus != ConnectionStatus.connected;

      _snapshot = ClientSnapshot(
        daemonAddr: daemonAddr,
        daemonVersion: status.daemonVersion.isEmpty
            ? 'unknown'
            : status.daemonVersion,
        status: preserveAwaiting ? ConnectionStatus.awaitingLogin : mappedStatus,
        activeProfile: activeProfile,
        profiles: profiles,
        networks: networks,
        settings: settings,
        pendingLogin: preserveAwaiting ? _snapshot.pendingLogin : null,
      );
    } catch (error) {
      _snapshot = _snapshot.copyWith(
        status: ConnectionStatus.error,
        errorMessage: _formatError(error),
      );
    }
    _emit();
  }

  Future<ProfileInfo> _loadActiveProfile() async {
    try {
      final active = await _client.getActiveProfile(
        daemon.GetActiveProfileRequest(),
        options: _options(),
      );
      if (active.profileName.isNotEmpty) {
        return ProfileInfo(
          name: active.profileName,
          email: _snapshot.activeProfile.email,
          active: true,
        );
      }
    } catch (_) {
      // Keep the status pane usable even when optional profile RPCs fail.
    }
    return _snapshot.activeProfile;
  }

  Future<List<ProfileInfo>> _loadProfiles(ProfileInfo activeProfile) async {
    try {
      final response = await _client.listProfiles(
        daemon.ListProfilesRequest(username: _username()),
        options: _options(),
      );
      final profiles = response.profiles.map((profile) {
        return ProfileInfo(name: profile.name, active: profile.isActive);
      }).toList();
      if (profiles.isNotEmpty) {
        return profiles;
      }
    } catch (_) {
      // Profile listing is not required for core connection status.
    }
    return [activeProfile];
  }

  Future<List<NetworkRoute>> _loadNetworks() async {
    try {
      final response = await _client.listNetworks(
        daemon.ListNetworksRequest(),
        options: _options(),
      );
      return _mapNetworks(response.routes);
    } catch (_) {
      return _snapshot.networks;
    }
  }

  Future<ClientSettings> _loadSettings(ProfileInfo activeProfile) async {
    try {
      final config = await _client.getConfig(
        daemon.GetConfigRequest(
          profileName: activeProfile.name,
          username: _username(),
        ),
        options: _options(),
      );
      return ClientSettings(
        managementUrl: config.managementUrl.isEmpty
            ? 'https://api.netbird.io'
            : config.managementUrl,
        interfaceName: config.interfaceName.isEmpty
            ? 'wt0'
            : config.interfaceName,
        wireguardPort: config.hasWireguardPort()
            ? config.wireguardPort.toInt()
            : 51820,
        mtu: config.hasMtu() ? config.mtu.toInt() : 1280,
        autoConnect: !config.disableAutoConnect,
        allowSsh: config.serverSSHAllowed,
        quantumResistance: config.rosenpassEnabled,
        notifications: !config.disableNotifications,
        lazyConnection: config.lazyConnectionEnabled,
        blockInbound: config.blockInbound,
      );
    } catch (_) {
      return _snapshot.settings;
    }
  }

  List<NetworkRoute> _mapNetworks(Iterable<daemon.Network> routes) {
    final rangeCounts = <String, int>{};
    for (final route in routes) {
      if (route.domains.isEmpty) {
        rangeCounts.update(
          route.range,
          (count) => count + 1,
          ifAbsent: () => 1,
        );
      }
    }

    return routes.map((route) {
        final resolvedIps = route.resolvedIPs.map((domain, ipList) {
          return MapEntry(domain, ipList.ips.toList());
        });

        return NetworkRoute(
          id: route.iD,
          range: route.range,
          selected: route.selected,
          domains: route.domains.toList(),
          resolvedIps: resolvedIps,
          overlapping:
              route.domains.isEmpty && (rangeCounts[route.range] ?? 0) > 1,
        );
      }).toList()
      ..sort((a, b) => a.id.toLowerCase().compareTo(b.id.toLowerCase()));
  }

  CallOptions _options({Duration? timeout}) {
    return CallOptions(timeout: timeout ?? _callTimeout);
  }

  void _setStatus(
    ConnectionStatus status, {
    bool clearError = false,
    bool clearPendingLogin = false,
  }) {
    _snapshot = _snapshot.copyWith(
      status: status,
      clearError: clearError,
      clearPendingLogin: clearPendingLogin,
    );
    _emit();
  }

  void _emit() {
    if (!_snapshots.isClosed) {
      _snapshots.add(_snapshot);
    }
  }
}

class FakeDaemonClient implements DaemonClient {
  FakeDaemonClient({required this.daemonAddr}) {
    scheduleMicrotask(_emit);
  }

  @override
  final String daemonAddr;

  final _snapshots = StreamController<ClientSnapshot>.broadcast();

  late ClientSnapshot _snapshot = ClientSnapshot.initial(daemonAddr).copyWith(
    daemonVersion: 'development',
    profiles: const [
      ProfileInfo(name: 'default', email: 'user@example.com', active: true),
      ProfileInfo(name: 'staging', active: false),
    ],
    networks: const [
      NetworkRoute(id: 'office', range: '10.10.0.0/16', selected: true),
      NetworkRoute(id: 'prod', range: '10.20.0.0/16'),
      NetworkRoute(id: 'exit-us', range: '0.0.0.0/0'),
    ],
  );

  @override
  Stream<ClientSnapshot> watchSnapshot() {
    scheduleMicrotask(_emit);
    return _snapshots.stream;
  }

  @override
  Stream<SystemNotification> watchEvents() =>
      const Stream<SystemNotification>.empty();

  @override
  Stream<UpdateProgressEvent> watchUpdateRequests() =>
      const Stream<UpdateProgressEvent>.empty();

  @override
  Future<void> connect() async {
    _snapshot = _snapshot.copyWith(status: ConnectionStatus.connecting);
    _emit();
    await Future<void>.delayed(const Duration(milliseconds: 450));
    _snapshot = _snapshot.copyWith(status: ConnectionStatus.connected);
    _emit();
  }

  @override
  Future<void> disconnect() async {
    _snapshot = _snapshot.copyWith(status: ConnectionStatus.disconnected);
    _emit();
  }

  @override
  Future<void> bringUp() async {
    _snapshot = _snapshot.copyWith(status: ConnectionStatus.connected);
    _emit();
  }

  @override
  Future<void> bringDown() async {
    _snapshot = _snapshot.copyWith(status: ConnectionStatus.disconnected);
    _emit();
  }

  @override
  Future<DebugBundleResult> debugBundle({
    required bool anonymize,
    required bool systemInfo,
    String? uploadUrl,
  }) async {
    await Future<void>.delayed(const Duration(milliseconds: 400));
    return DebugBundleResult(
      path: '/tmp/netbird-debug.tar.gz',
      uploadedKey: uploadUrl == null ? '' : 'fake-upload-key',
    );
  }

  @override
  Future<DaemonLogLevel> getLogLevel() async => DaemonLogLevel.info;

  @override
  Future<void> setLogLevel(DaemonLogLevel level) async {}

  @override
  Future<void> setSyncResponsePersistence(bool enabled) async {}

  @override
  Future<void> startCpuProfile() async {}

  @override
  Future<void> stopCpuProfile() async {}

  @override
  Future<TriggerUpdateResult> triggerUpdate() async {
    return const TriggerUpdateResult(success: true);
  }

  @override
  Future<InstallerResult> getInstallerResult() async {
    await Future<void>.delayed(const Duration(seconds: 2));
    return const InstallerResult(success: true);
  }

  @override
  Future<void> updateSettings(ClientSettings updated) async {
    _snapshot = _snapshot.copyWith(settings: updated);
    _emit();
  }

  @override
  Future<void> setNetworkSelection(String routeId, bool selected) async {
    final next = _snapshot.networks.map((route) {
      if (route.id != routeId) {
        return route;
      }
      return NetworkRoute(
        id: route.id,
        range: route.range,
        domains: route.domains,
        resolvedIps: route.resolvedIps,
        overlapping: route.overlapping,
        selected: selected,
      );
    }).toList();
    _snapshot = _snapshot.copyWith(networks: next);
    _emit();
  }

  @override
  Future<void> setExitNode(String? routeId) async {
    final next = _snapshot.networks.map((route) {
      if (!route.isExitNode) {
        return route;
      }
      return NetworkRoute(
        id: route.id,
        range: route.range,
        domains: route.domains,
        resolvedIps: route.resolvedIps,
        overlapping: route.overlapping,
        selected: route.id == routeId,
      );
    }).toList();
    _snapshot = _snapshot.copyWith(networks: next);
    _emit();
  }

  @override
  Future<void> switchProfile(String name) async {
    final profiles = _snapshot.profiles.map((profile) {
      return ProfileInfo(
        name: profile.name,
        email: profile.email,
        active: profile.name == name,
      );
    }).toList();
    final active = profiles.firstWhere(
      (profile) => profile.active,
      orElse: () => _snapshot.activeProfile,
    );
    _snapshot = _snapshot.copyWith(profiles: profiles, activeProfile: active);
    _emit();
  }

  @override
  Future<void> addProfile(String name) async {
    final profiles = [
      ..._snapshot.profiles,
      ProfileInfo(name: name, active: false),
    ];
    _snapshot = _snapshot.copyWith(profiles: profiles);
    _emit();
  }

  @override
  Future<void> removeProfile(String name) async {
    final profiles = _snapshot.profiles
        .where((profile) => profile.name != name)
        .toList();
    _snapshot = _snapshot.copyWith(profiles: profiles);
    _emit();
  }

  @override
  Future<void> logoutActive() async {
    _snapshot = _snapshot.copyWith(status: ConnectionStatus.disconnected);
    _emit();
  }

  @override
  void dispose() {
    _snapshots.close();
  }

  void _emit() {
    if (!_snapshots.isClosed) {
      _snapshots.add(_snapshot);
    }
  }
}

ClientChannel _createChannel(String daemonAddr) {
  final options = ChannelOptions(
    credentials: const ChannelCredentials.insecure(),
    userAgent: _userAgent,
    connectTimeout: const Duration(seconds: 3),
  );

  if (daemonAddr.startsWith('unix://')) {
    final path = daemonAddr.substring('unix://'.length);
    return ClientChannel(
      InternetAddress(path, type: InternetAddressType.unix),
      port: 0,
      options: options,
    );
  }

  final uri = daemonAddr.contains('://')
      ? Uri.parse(daemonAddr)
      : Uri.parse('tcp://$daemonAddr');
  final host = uri.host.isEmpty ? '127.0.0.1' : uri.host;
  final port = uri.hasPort ? uri.port : 41731;
  return ClientChannel(host, port: port, options: options);
}

ConnectionStatus _mapStatus(String status) {
  return switch (status) {
    'Connected' => ConnectionStatus.connected,
    'Connecting' => ConnectionStatus.connecting,
    'Idle' || 'SessionExpired' => ConnectionStatus.disconnected,
    _ => ConnectionStatus.error,
  };
}

String _username() {
  if (Platform.isWindows) {
    final username = Platform.environment['USERNAME'] ?? '';
    final domain = Platform.environment['USERDOMAIN'] ?? '';
    if (domain.isNotEmpty && username.isNotEmpty) {
      return '$domain\\$username';
    }
    return username;
  }
  return Platform.environment['USER'] ?? Platform.environment['LOGNAME'] ?? '';
}

String _formatError(Object error) {
  if (error is GrpcError) {
    return error.message ?? error.toString();
  }
  return error.toString();
}
