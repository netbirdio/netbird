enum ConnectionStatus {
  disconnected,
  connecting,
  awaitingLogin,
  connected,
  error;

  String get label {
    return switch (this) {
      ConnectionStatus.disconnected => 'Disconnected',
      ConnectionStatus.connecting => 'Connecting',
      ConnectionStatus.awaitingLogin => 'Awaiting login',
      ConnectionStatus.connected => 'Connected',
      ConnectionStatus.error => 'Error',
    };
  }
}

enum NetworkFilter {
  all,
  overlapping,
  exitNode;

  bool matches(NetworkRoute route) {
    return switch (this) {
      NetworkFilter.all => true,
      NetworkFilter.overlapping => route.overlapping,
      NetworkFilter.exitNode => route.isExitNode,
    };
  }
}

class ClientSnapshot {
  const ClientSnapshot({
    required this.daemonAddr,
    required this.daemonVersion,
    required this.status,
    required this.activeProfile,
    required this.profiles,
    required this.networks,
    required this.settings,
    this.errorMessage,
    this.pendingLogin,
  });

  factory ClientSnapshot.initial(String daemonAddr) {
    return ClientSnapshot(
      daemonAddr: daemonAddr,
      daemonVersion: 'unknown',
      status: ConnectionStatus.disconnected,
      activeProfile: const ProfileInfo(name: 'default', active: true),
      profiles: const [ProfileInfo(name: 'default', active: true)],
      networks: const [],
      settings: const ClientSettings(),
    );
  }

  final String daemonAddr;
  final String daemonVersion;
  final ConnectionStatus status;
  final ProfileInfo activeProfile;
  final List<ProfileInfo> profiles;
  final List<NetworkRoute> networks;
  final ClientSettings settings;
  final String? errorMessage;
  final PendingLogin? pendingLogin;

  ClientSnapshot copyWith({
    String? daemonAddr,
    String? daemonVersion,
    ConnectionStatus? status,
    ProfileInfo? activeProfile,
    List<ProfileInfo>? profiles,
    List<NetworkRoute>? networks,
    ClientSettings? settings,
    String? errorMessage,
    PendingLogin? pendingLogin,
    bool clearError = false,
    bool clearPendingLogin = false,
  }) {
    return ClientSnapshot(
      daemonAddr: daemonAddr ?? this.daemonAddr,
      daemonVersion: daemonVersion ?? this.daemonVersion,
      status: status ?? this.status,
      activeProfile: activeProfile ?? this.activeProfile,
      profiles: profiles ?? this.profiles,
      networks: networks ?? this.networks,
      settings: settings ?? this.settings,
      errorMessage: clearError ? null : errorMessage ?? this.errorMessage,
      pendingLogin: clearPendingLogin
          ? null
          : pendingLogin ?? this.pendingLogin,
    );
  }
}

class PendingLogin {
  const PendingLogin({
    required this.verificationUri,
    required this.userCode,
  });

  final String verificationUri;
  final String userCode;
}

class ProfileInfo {
  const ProfileInfo({required this.name, required this.active, this.email});

  final String name;
  final String? email;
  final bool active;
}

class NetworkRoute {
  const NetworkRoute({
    required this.id,
    required this.range,
    this.domains = const [],
    this.resolvedIps = const {},
    this.selected = false,
    this.overlapping = false,
  });

  final String id;
  final String range;
  final List<String> domains;
  final Map<String, List<String>> resolvedIps;
  final bool selected;
  final bool overlapping;

  bool get isExitNode => range == '0.0.0.0/0';
}

enum DaemonLogLevel { unknown, panic, fatal, error, warn, info, debug, trace }

class DebugBundleResult {
  const DebugBundleResult({
    required this.path,
    this.uploadedKey = '',
    this.uploadFailureReason = '',
  });

  final String path;
  final String uploadedKey;
  final String uploadFailureReason;

  bool get uploaded => uploadedKey.isNotEmpty && uploadFailureReason.isEmpty;
  bool get uploadFailed => uploadFailureReason.isNotEmpty;
}

class TriggerUpdateResult {
  const TriggerUpdateResult({required this.success, this.errorMessage = ''});

  final bool success;
  final String errorMessage;
}

class InstallerResult {
  const InstallerResult({required this.success, this.errorMessage = ''});

  final bool success;
  final String errorMessage;
}

class UpdateProgressEvent {
  const UpdateProgressEvent({required this.version});
  final String version;
}

enum NotificationSeverity { info, warning, error, critical }

enum NotificationCategory {
  network,
  dns,
  authentication,
  connectivity,
  system;

  String get label {
    return switch (this) {
      NotificationCategory.network => 'Network',
      NotificationCategory.dns => 'DNS',
      NotificationCategory.authentication => 'Authentication',
      NotificationCategory.connectivity => 'Connectivity',
      NotificationCategory.system => 'System',
    };
  }
}

class SystemNotification {
  const SystemNotification({
    required this.severity,
    required this.category,
    required this.message,
    required this.userMessage,
    this.id,
  });

  final NotificationSeverity severity;
  final NotificationCategory category;
  final String message;
  final String userMessage;
  final String? id;
}

class ClientSettings {
  const ClientSettings({
    this.managementUrl = 'https://api.netbird.io',
    this.interfaceName = 'wt0',
    this.wireguardPort = 51820,
    this.mtu = 1280,
    this.autoConnect = true,
    this.allowSsh = false,
    this.quantumResistance = false,
    this.notifications = true,
    this.lazyConnection = false,
    this.blockInbound = false,
  });

  final String managementUrl;
  final String interfaceName;
  final int wireguardPort;
  final int mtu;
  final bool autoConnect;
  final bool allowSsh;
  final bool quantumResistance;
  final bool notifications;
  final bool lazyConnection;
  final bool blockInbound;

  ClientSettings copyWith({
    String? managementUrl,
    String? interfaceName,
    int? wireguardPort,
    int? mtu,
    bool? autoConnect,
    bool? allowSsh,
    bool? quantumResistance,
    bool? notifications,
    bool? lazyConnection,
    bool? blockInbound,
  }) {
    return ClientSettings(
      managementUrl: managementUrl ?? this.managementUrl,
      interfaceName: interfaceName ?? this.interfaceName,
      wireguardPort: wireguardPort ?? this.wireguardPort,
      mtu: mtu ?? this.mtu,
      autoConnect: autoConnect ?? this.autoConnect,
      allowSsh: allowSsh ?? this.allowSsh,
      quantumResistance: quantumResistance ?? this.quantumResistance,
      notifications: notifications ?? this.notifications,
      lazyConnection: lazyConnection ?? this.lazyConnection,
      blockInbound: blockInbound ?? this.blockInbound,
    );
  }
}
