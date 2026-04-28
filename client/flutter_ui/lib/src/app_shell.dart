import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'daemon_client.dart';
import 'debug_screen.dart';
import 'desktop_integration.dart';
import 'models.dart';
import 'platform.dart';
import 'update_progress.dart';

class NetBirdFlutterApp extends StatelessWidget {
  const NetBirdFlutterApp({required this.client, this.integration, super.key});

  final DaemonClient client;
  final DesktopIntegration? integration;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NetBird',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF008C95),
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF008C95),
        brightness: Brightness.dark,
      ),
      home: AppShell(client: client, integration: integration),
    );
  }
}

class AppShell extends StatefulWidget {
  const AppShell({required this.client, this.integration, super.key});

  final DaemonClient client;
  final DesktopIntegration? integration;

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  late ClientSnapshot _snapshot;
  StreamSubscription<ClientSnapshot>? _subscription;
  StreamSubscription<UpdateProgressEvent>? _updateSubscription;
  StreamSubscription<int>? _tabSubscription;
  int _selectedIndex = 0;
  bool _busy = false;
  bool _updateDialogOpen = false;

  @override
  void initState() {
    super.initState();
    _snapshot = ClientSnapshot.initial(widget.client.daemonAddr);
    _subscription = widget.client.watchSnapshot().listen((snapshot) {
      if (!mounted) {
        return;
      }
      setState(() => _snapshot = snapshot);
    });
    _updateSubscription = widget.client.watchUpdateRequests().listen(
      _showUpdateDialog,
    );
    _tabSubscription = widget.integration?.tabRequests.listen((index) {
      if (!mounted) {
        return;
      }
      setState(() => _selectedIndex = index);
    });
  }

  @override
  void dispose() {
    _subscription?.cancel();
    _updateSubscription?.cancel();
    _tabSubscription?.cancel();
    widget.client.dispose();
    super.dispose();
  }

  Future<void> _showUpdateDialog(UpdateProgressEvent event) async {
    if (!mounted || _updateDialogOpen) {
      return;
    }
    _updateDialogOpen = true;
    try {
      await showUpdateProgressDialog(
        context: context,
        client: widget.client,
        event: event,
      );
    } finally {
      if (mounted) {
        _updateDialogOpen = false;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: _selectedIndex,
            onDestinationSelected: (index) {
              setState(() => _selectedIndex = index);
            },
            labelType: NavigationRailLabelType.all,
            leading: Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: _StatusGlyph(status: _snapshot.status),
            ),
            destinations: const [
              NavigationRailDestination(
                icon: Icon(Icons.hub_outlined),
                selectedIcon: Icon(Icons.hub),
                label: Text('Status'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.route_outlined),
                selectedIcon: Icon(Icons.route),
                label: Text('Networks'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.account_circle_outlined),
                selectedIcon: Icon(Icons.account_circle),
                label: Text('Profiles'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.tune_outlined),
                selectedIcon: Icon(Icons.tune),
                label: Text('Settings'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.bug_report_outlined),
                selectedIcon: Icon(Icons.bug_report),
                label: Text('Debug'),
              ),
            ],
          ),
          const VerticalDivider(width: 1),
          Expanded(child: SafeArea(child: _buildPage(context))),
        ],
      ),
    );
  }

  Widget _buildPage(BuildContext context) {
    return switch (_selectedIndex) {
      0 => _StatusPane(
        snapshot: _snapshot,
        busy: _busy,
        onConnect: () => _run(widget.client.connect),
        onDisconnect: () => _run(widget.client.disconnect),
      ),
      1 => _NetworksPane(snapshot: _snapshot, client: widget.client),
      2 => _ProfilesPane(snapshot: _snapshot, client: widget.client),
      3 => _SettingsPane(snapshot: _snapshot, client: widget.client),
      _ => DebugScreen(client: widget.client),
    };
  }

  Future<void> _run(Future<void> Function() action) async {
    if (_busy) {
      return;
    }
    setState(() => _busy = true);
    try {
      await action();
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }
}

class _Page extends StatelessWidget {
  const _Page({required this.title, required this.child, this.actions});

  final String title;
  final Widget child;
  final List<Widget>? actions;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  title,
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
              ),
              if (actions != null) ...actions!,
            ],
          ),
          const SizedBox(height: 20),
          Expanded(child: child),
        ],
      ),
    );
  }
}

class _StatusPane extends StatelessWidget {
  const _StatusPane({
    required this.snapshot,
    required this.busy,
    required this.onConnect,
    required this.onDisconnect,
  });

  final ClientSnapshot snapshot;
  final bool busy;
  final VoidCallback onConnect;
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    final connected = snapshot.status == ConnectionStatus.connected;
    final connecting =
        snapshot.status == ConnectionStatus.connecting ||
        snapshot.status == ConnectionStatus.awaitingLogin;

    return _Page(
      title: 'Status',
      child: ListView(
        children: [
          _InfoRow(label: 'Connection', value: snapshot.status.label),
          _InfoRow(label: 'Daemon', value: snapshot.daemonAddr),
          _InfoRow(label: 'Daemon version', value: snapshot.daemonVersion),
          if (snapshot.pendingLogin != null) ...[
            const SizedBox(height: 16),
            _LoginBanner(pending: snapshot.pendingLogin!),
          ],
          if (snapshot.errorMessage != null) ...[
            const SizedBox(height: 16),
            _ErrorBanner(message: snapshot.errorMessage!),
          ],
          const SizedBox(height: 24),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              FilledButton.icon(
                onPressed: busy || connected || connecting ? null : onConnect,
                icon: const Icon(Icons.power_settings_new),
                label: const Text('Connect'),
              ),
              OutlinedButton.icon(
                onPressed: busy || !connected ? null : onDisconnect,
                icon: const Icon(Icons.power_off),
                label: const Text('Disconnect'),
              ),
            ],
          ),
          const SizedBox(height: 32),
          _SectionLabel('Active profile'),
          _ProfileTile(profile: snapshot.activeProfile),
        ],
      ),
    );
  }
}

class _NetworksPane extends StatefulWidget {
  const _NetworksPane({required this.snapshot, required this.client});

  final ClientSnapshot snapshot;
  final DaemonClient client;

  @override
  State<_NetworksPane> createState() => _NetworksPaneState();
}

class _NetworksPaneState extends State<_NetworksPane> {
  NetworkFilter _filter = NetworkFilter.all;
  final Set<String> _busyRoutes = {};

  @override
  Widget build(BuildContext context) {
    final networks = widget.snapshot.networks
        .where(_filter.matches)
        .toList();

    return _Page(
      title: 'Networks',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SegmentedButton<NetworkFilter>(
            segments: const [
              ButtonSegment(
                value: NetworkFilter.all,
                icon: Icon(Icons.all_inclusive),
                label: Text('All'),
              ),
              ButtonSegment(
                value: NetworkFilter.overlapping,
                icon: Icon(Icons.compare_arrows),
                label: Text('Overlapping'),
              ),
              ButtonSegment(
                value: NetworkFilter.exitNode,
                icon: Icon(Icons.public),
                label: Text('Exit nodes'),
              ),
            ],
            selected: {_filter},
            onSelectionChanged: (selected) {
              setState(() => _filter = selected.single);
            },
          ),
          const SizedBox(height: 16),
          if (networks.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 24),
              child: Text('No networks to show.'),
            )
          else
            Expanded(
              child: ListView.separated(
                itemCount: networks.length,
                separatorBuilder: (_, _) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final route = networks[index];
                  final exitNodeMode = _filter == NetworkFilter.exitNode;
                  return _NetworkTile(
                    route: route,
                    exitNodeMode: exitNodeMode,
                    busy: _busyRoutes.contains(route.id),
                    onChanged: (selected) =>
                        _toggle(route, selected, exitNodeMode),
                  );
                },
              ),
            ),
        ],
      ),
    );
  }

  Future<void> _toggle(
    NetworkRoute route,
    bool selected,
    bool exitNodeMode,
  ) async {
    if (_busyRoutes.contains(route.id)) {
      return;
    }
    setState(() => _busyRoutes.add(route.id));
    try {
      if (exitNodeMode) {
        await widget.client.setExitNode(selected ? route.id : null);
      } else {
        await widget.client.setNetworkSelection(route.id, selected);
      }
    } finally {
      if (mounted) {
        setState(() => _busyRoutes.remove(route.id));
      }
    }
  }
}

class _ProfilesPane extends StatefulWidget {
  const _ProfilesPane({required this.snapshot, required this.client});

  final ClientSnapshot snapshot;
  final DaemonClient client;

  @override
  State<_ProfilesPane> createState() => _ProfilesPaneState();
}

class _ProfilesPaneState extends State<_ProfilesPane> {
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    return _Page(
      title: 'Profiles',
      actions: [
        FilledButton.tonalIcon(
          onPressed: _busy ? null : _showAddDialog,
          icon: const Icon(Icons.add),
          label: const Text('Add profile'),
        ),
      ],
      child: ListView.separated(
        itemCount: widget.snapshot.profiles.length,
        separatorBuilder: (_, _) => const Divider(height: 1),
        itemBuilder: (context, index) {
          final profile = widget.snapshot.profiles[index];
          return _ProfileTile(
            profile: profile,
            onTap: profile.active || _busy ? null : () => _confirmSwitch(profile),
            trailing: _profileMenu(profile),
          );
        },
      ),
    );
  }

  Widget _profileMenu(ProfileInfo profile) {
    return PopupMenuButton<_ProfileAction>(
      enabled: !_busy,
      onSelected: (action) => _handleAction(action, profile),
      itemBuilder: (context) => [
        if (profile.active)
          const PopupMenuItem(
            value: _ProfileAction.logout,
            child: ListTile(
              leading: Icon(Icons.logout),
              title: Text('Logout'),
              contentPadding: EdgeInsets.zero,
            ),
          ),
        PopupMenuItem(
          value: _ProfileAction.remove,
          enabled: !profile.active,
          child: const ListTile(
            leading: Icon(Icons.delete_outline),
            title: Text('Remove'),
            contentPadding: EdgeInsets.zero,
          ),
        ),
      ],
    );
  }

  Future<void> _handleAction(
    _ProfileAction action,
    ProfileInfo profile,
  ) async {
    switch (action) {
      case _ProfileAction.logout:
        await _confirmAndRun(
          title: 'Logout from ${profile.name}?',
          message:
              'This disconnects the active profile and clears its session.',
          run: widget.client.logoutActive,
        );
      case _ProfileAction.remove:
        await _confirmAndRun(
          title: 'Remove profile ${profile.name}?',
          message: 'This deletes the profile from this device.',
          run: () => widget.client.removeProfile(profile.name),
        );
    }
  }

  Future<void> _confirmSwitch(ProfileInfo profile) async {
    await _confirmAndRun(
      title: 'Switch to ${profile.name}?',
      message: 'The connection will restart with the new profile.',
      run: () => widget.client.switchProfile(profile.name),
    );
  }

  Future<void> _showAddDialog() async {
    final controller = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Add profile'),
          content: TextField(
            controller: controller,
            autofocus: true,
            decoration: const InputDecoration(labelText: 'Profile name'),
            onSubmitted: (value) => Navigator.of(context).pop(value.trim()),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () =>
                  Navigator.of(context).pop(controller.text.trim()),
              child: const Text('Add'),
            ),
          ],
        );
      },
    );
    if (name == null || name.isEmpty) {
      return;
    }
    await _runBusy(() => widget.client.addProfile(name));
  }

  Future<void> _confirmAndRun({
    required String title,
    required String message,
    required Future<void> Function() run,
  }) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: Text(title),
          content: Text(message),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Confirm'),
            ),
          ],
        );
      },
    );
    if (confirm != true) {
      return;
    }
    await _runBusy(run);
  }

  Future<void> _runBusy(Future<void> Function() action) async {
    if (_busy) {
      return;
    }
    setState(() => _busy = true);
    try {
      await action();
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }
}

enum _ProfileAction { logout, remove }

class _SettingsPane extends StatefulWidget {
  const _SettingsPane({required this.snapshot, required this.client});

  final ClientSnapshot snapshot;
  final DaemonClient client;

  @override
  State<_SettingsPane> createState() => _SettingsPaneState();
}

class _SettingsPaneState extends State<_SettingsPane> {
  bool _writing = false;

  @override
  Widget build(BuildContext context) {
    final settings = widget.snapshot.settings;
    final disabled = _writing;

    return _Page(
      title: 'Settings',
      child: ListView(
        children: [
          _InfoRow(label: 'Management URL', value: settings.managementUrl),
          _InfoRow(label: 'Interface', value: settings.interfaceName),
          _InfoRow(label: 'WireGuard port', value: '${settings.wireguardPort}'),
          _InfoRow(label: 'MTU', value: '${settings.mtu}'),
          const SizedBox(height: 16),
          SwitchListTile(
            value: settings.autoConnect,
            onChanged: disabled
                ? null
                : (value) =>
                    _apply(settings.copyWith(autoConnect: value)),
            title: const Text('Connect on startup'),
          ),
          SwitchListTile(
            value: settings.allowSsh,
            onChanged: disabled
                ? null
                : (value) => _apply(settings.copyWith(allowSsh: value)),
            title: const Text('Allow SSH'),
          ),
          SwitchListTile(
            value: settings.quantumResistance,
            onChanged: disabled
                ? null
                : (value) =>
                    _apply(settings.copyWith(quantumResistance: value)),
            title: const Text('Quantum resistance'),
          ),
          SwitchListTile(
            value: settings.lazyConnection,
            onChanged: disabled
                ? null
                : (value) =>
                    _apply(settings.copyWith(lazyConnection: value)),
            title: const Text('Lazy connections'),
          ),
          SwitchListTile(
            value: settings.blockInbound,
            onChanged: disabled
                ? null
                : (value) =>
                    _apply(settings.copyWith(blockInbound: value)),
            title: const Text('Block inbound'),
          ),
          SwitchListTile(
            value: settings.notifications,
            onChanged: disabled
                ? null
                : (value) =>
                    _apply(settings.copyWith(notifications: value)),
            title: const Text('Notifications'),
          ),
        ],
      ),
    );
  }

  Future<void> _apply(ClientSettings updated) async {
    setState(() => _writing = true);
    try {
      await widget.client.updateSettings(updated);
    } finally {
      if (mounted) {
        setState(() => _writing = false);
      }
    }
  }
}

class _StatusGlyph extends StatelessWidget {
  const _StatusGlyph({required this.status});

  final ConnectionStatus status;

  @override
  Widget build(BuildContext context) {
    final color = switch (status) {
      ConnectionStatus.connected => Colors.green,
      ConnectionStatus.connecting => Colors.amber,
      ConnectionStatus.awaitingLogin => Colors.lightBlue,
      ConnectionStatus.error => Colors.red,
      ConnectionStatus.disconnected => Colors.grey,
    };

    return Tooltip(
      message: status.label,
      child: Icon(Icons.circle, color: color, size: 18),
    );
  }
}

class _InfoRow extends StatelessWidget {
  const _InfoRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 160,
            child: Text(label, style: Theme.of(context).textTheme.labelLarge),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  const _SectionLabel(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(text, style: Theme.of(context).textTheme.titleMedium),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(Icons.error_outline, color: colors.onErrorContainer),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                message,
                style: TextStyle(color: colors.onErrorContainer),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _LoginBanner extends StatelessWidget {
  const _LoginBanner({required this.pending});

  final PendingLogin pending;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.tertiaryContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Sign in to continue',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: colors.onTertiaryContainer,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'A browser window opened to complete sign-in. '
              'If it did not, open the URL below.',
              style: TextStyle(color: colors.onTertiaryContainer),
            ),
            const SizedBox(height: 12),
            SelectableText(
              pending.verificationUri,
              style: TextStyle(color: colors.onTertiaryContainer),
            ),
            const SizedBox(height: 4),
            Text(
              'Code: ${pending.userCode}',
              style: TextStyle(color: colors.onTertiaryContainer),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              children: [
                FilledButton.tonalIcon(
                  onPressed: () => _openUrl(pending.verificationUri),
                  icon: const Icon(Icons.open_in_new),
                  label: const Text('Open in browser'),
                ),
                OutlinedButton.icon(
                  onPressed: () => _copy(context, pending.verificationUri),
                  icon: const Icon(Icons.copy),
                  label: const Text('Copy URL'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _openUrl(String url) async {
    await openExternalUrl(url);
  }

  Future<void> _copy(BuildContext context, String url) async {
    await Clipboard.setData(ClipboardData(text: url));
    if (!context.mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('URL copied')),
    );
  }
}

class _NetworkTile extends StatelessWidget {
  const _NetworkTile({
    required this.route,
    required this.exitNodeMode,
    required this.busy,
    required this.onChanged,
  });

  final NetworkRoute route;
  final bool exitNodeMode;
  final bool busy;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final subtitle = [
      route.range,
      if (route.domains.isNotEmpty) route.domains.join(', '),
    ].join(' ');

    Widget leading;
    if (busy) {
      leading = const SizedBox(
        width: 24,
        height: 24,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    } else if (exitNodeMode) {
      leading = IconButton(
        icon: Icon(
          route.selected
              ? Icons.radio_button_checked
              : Icons.radio_button_unchecked,
        ),
        onPressed: () => onChanged(!route.selected),
      );
    } else {
      leading = Checkbox(
        value: route.selected,
        onChanged: (value) => onChanged(value ?? false),
      );
    }

    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: leading,
      title: Text(route.id),
      subtitle: Text(subtitle),
      trailing: route.isExitNode ? const Icon(Icons.public) : null,
      onTap: busy ? null : () => onChanged(!route.selected),
    );
  }
}

class _ProfileTile extends StatelessWidget {
  const _ProfileTile({required this.profile, this.onTap, this.trailing});

  final ProfileInfo profile;
  final VoidCallback? onTap;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(
        profile.active ? Icons.check_circle : Icons.circle_outlined,
      ),
      title: Text(profile.name),
      subtitle: profile.email == null ? null : Text(profile.email!),
      onTap: onTap,
      trailing: trailing,
    );
  }
}
