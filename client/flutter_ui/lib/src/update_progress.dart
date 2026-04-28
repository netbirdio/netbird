import 'dart:async';

import 'package:flutter/material.dart';

import 'daemon_client.dart';
import 'models.dart';

const _allowCloseAfter = Duration(seconds: 10);
const _dotInterval = Duration(seconds: 1);

/// Shows a modal dialog while the daemon installs an update. Polls
/// `GetInstallerResult` and resolves when the daemon finishes or fails.
Future<void> showUpdateProgressDialog({
  required BuildContext context,
  required DaemonClient client,
  required UpdateProgressEvent event,
}) {
  return showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => _UpdateProgressDialog(client: client, event: event),
  );
}

class _UpdateProgressDialog extends StatefulWidget {
  const _UpdateProgressDialog({required this.client, required this.event});

  final DaemonClient client;
  final UpdateProgressEvent event;

  @override
  State<_UpdateProgressDialog> createState() => _UpdateProgressDialogState();
}

class _UpdateProgressDialogState extends State<_UpdateProgressDialog> {
  Timer? _dotTimer;
  Timer? _allowCloseTimer;
  int _dots = 0;
  bool _canClose = false;
  String _status = 'Updating';
  String? _error;
  bool _resolved = false;

  @override
  void initState() {
    super.initState();
    _dotTimer = Timer.periodic(_dotInterval, (_) => _tick());
    _allowCloseTimer = Timer(_allowCloseAfter, () {
      if (mounted) {
        setState(() => _canClose = true);
      }
    });
    unawaited(_pollInstaller());
  }

  @override
  void dispose() {
    _dotTimer?.cancel();
    _allowCloseTimer?.cancel();
    super.dispose();
  }

  void _tick() {
    if (!mounted) {
      return;
    }
    setState(() {
      _dots = (_dots + 1) % 4;
      _status = 'Updating${'.' * _dots}';
    });
  }

  Future<void> _pollInstaller() async {
    try {
      final result = await widget.client.getInstallerResult();
      if (!mounted) {
        return;
      }
      if (result.success) {
        Navigator.of(context).pop();
        return;
      }
      setState(() {
        _resolved = true;
        _canClose = true;
        _status = 'Update failed';
        _error = result.errorMessage.isEmpty
            ? 'Unknown error'
            : result.errorMessage;
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _resolved = true;
        _canClose = true;
        _status = 'Update timed out';
        _error = error.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: _canClose,
      child: AlertDialog(
        title: const Text('Updating client'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Your client version is older than the auto-update version set in '
              'Management.\nUpdating client to ${widget.event.version}.',
            ),
            const SizedBox(height: 16),
            if (!_resolved) const LinearProgressIndicator(),
            const SizedBox(height: 12),
            Text(_status),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: _canClose ? () => Navigator.of(context).pop() : null,
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}
