import 'dart:io';

import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'src/app_shell.dart';
import 'src/daemon_client.dart';
import 'src/desktop_integration.dart';

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();

  final daemonAddr = _readFlag(args, 'daemon-addr') ?? _defaultDaemonAddr();
  final fakeDaemon = args.contains('--fake-daemon');

  await windowManager.ensureInitialized();
  const windowOptions = WindowOptions(
    size: Size(900, 640),
    minimumSize: Size(720, 520),
    center: true,
    title: 'NetBird',
  );
  await windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
  });

  final client = fakeDaemon
      ? FakeDaemonClient(daemonAddr: daemonAddr)
      : GrpcDaemonClient(daemonAddr: daemonAddr);

  final integration = DesktopIntegration(client: client);
  await integration.initialize();

  runApp(NetBirdFlutterApp(client: client, integration: integration));
}

String? _readFlag(List<String> args, String name) {
  final prefix = '--$name=';
  for (final arg in args) {
    if (arg.startsWith(prefix)) {
      return arg.substring(prefix.length);
    }
  }
  return null;
}

String _defaultDaemonAddr() {
  if (Platform.isWindows) {
    return 'tcp://127.0.0.1:41731';
  }
  return 'unix:///var/run/netbird.sock';
}
