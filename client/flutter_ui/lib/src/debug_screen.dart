import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'daemon_client.dart';
import 'models.dart';
import 'platform.dart';

const _defaultUploadUrl = 'https://upload.netbird.io/';

class DebugScreen extends StatefulWidget {
  const DebugScreen({required this.client, super.key});

  final DaemonClient client;

  @override
  State<DebugScreen> createState() => _DebugScreenState();
}

class _DebugScreenState extends State<DebugScreen> {
  final _uploadUrlController =
      TextEditingController(text: _defaultUploadUrl);
  final _durationController = TextEditingController(text: '1');

  bool _anonymize = false;
  bool _systemInfo = true;
  bool _upload = true;
  bool _runWithTrace = true;
  bool _busy = false;

  String _status = '';
  double? _progress;

  @override
  void dispose() {
    _uploadUrlController.dispose();
    _durationController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Debug', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 16),
          Text(
            'Create a debug bundle to help troubleshoot issues with NetBird.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 24),
          Expanded(
            child: ListView(
              children: [
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _anonymize,
                  onChanged: _busy
                      ? null
                      : (value) => setState(() => _anonymize = value ?? false),
                  title: const Text(
                    'Anonymize sensitive information (public IPs, domains, ...)',
                  ),
                ),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _systemInfo,
                  onChanged: _busy
                      ? null
                      : (value) => setState(() => _systemInfo = value ?? false),
                  title: const Text(
                    'Include system information (routes, interfaces, ...)',
                  ),
                ),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _upload,
                  onChanged: _busy
                      ? null
                      : (value) => setState(() => _upload = value ?? false),
                  title: const Text('Upload bundle automatically after creation'),
                ),
                if (_upload)
                  Padding(
                    padding: const EdgeInsets.only(left: 32, bottom: 8, top: 4),
                    child: TextField(
                      controller: _uploadUrlController,
                      enabled: !_busy,
                      decoration: const InputDecoration(
                        labelText: 'Debug upload URL',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ),
                const Divider(height: 32),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _runWithTrace,
                  onChanged: _busy
                      ? null
                      : (value) =>
                          setState(() => _runWithTrace = value ?? false),
                  title: const Text(
                    'Run with trace logs before creating bundle',
                  ),
                ),
                if (_runWithTrace)
                  Padding(
                    padding: const EdgeInsets.only(left: 32, top: 4),
                    child: Row(
                      children: [
                        const Text('Run for'),
                        const SizedBox(width: 12),
                        SizedBox(
                          width: 80,
                          child: TextField(
                            controller: _durationController,
                            enabled: !_busy,
                            keyboardType: TextInputType.number,
                            inputFormatters: [
                              FilteringTextInputFormatter.digitsOnly,
                            ],
                            decoration: const InputDecoration(
                              isDense: true,
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(_durationLabel()),
                      ],
                    ),
                  ),
                if (_runWithTrace)
                  const Padding(
                    padding: EdgeInsets.only(left: 32, top: 8),
                    child: Text(
                      'Note: NetBird will be brought up and down during collection.',
                      style: TextStyle(fontStyle: FontStyle.italic),
                    ),
                  ),
                const SizedBox(height: 24),
                if (_status.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Text(_status),
                  ),
                if (_progress != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: LinearProgressIndicator(value: _progress),
                  ),
                Align(
                  alignment: Alignment.centerLeft,
                  child: FilledButton.icon(
                    onPressed: _busy ? null : _onCreate,
                    icon: _busy
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.archive_outlined),
                    label: const Text('Create Debug Bundle'),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _durationLabel() {
    final value = int.tryParse(_durationController.text) ?? 0;
    return value == 1 ? 'minute' : 'minutes';
  }

  Future<void> _onCreate() async {
    final uploadUrl = _upload ? _uploadUrlController.text.trim() : null;
    if (_upload && (uploadUrl == null || uploadUrl.isEmpty)) {
      setState(() => _status = 'Upload URL is required when upload is enabled');
      return;
    }

    Duration? traceDuration;
    if (_runWithTrace) {
      final minutes = int.tryParse(_durationController.text);
      if (minutes == null || minutes < 1) {
        setState(() => _status = 'Duration must be a number ≥ 1');
        return;
      }
      traceDuration = Duration(minutes: minutes);
    }

    setState(() {
      _busy = true;
      _status = '';
      _progress = null;
    });

    try {
      DebugBundleResult result;
      if (traceDuration != null) {
        result = await _runWithTraceLogs(
          duration: traceDuration,
          uploadUrl: uploadUrl,
        );
      } else {
        setState(() => _status = 'Creating debug bundle...');
        result = await widget.client.debugBundle(
          anonymize: _anonymize,
          systemInfo: _systemInfo,
          uploadUrl: uploadUrl,
        );
      }
      if (!mounted) {
        return;
      }
      setState(() => _status = 'Bundle created successfully');
      await _showResultDialog(result);
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _status = 'Error: $error';
        _progress = null;
      });
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  Future<DebugBundleResult> _runWithTraceLogs({
    required Duration duration,
    required String? uploadUrl,
  }) async {
    final initialLevel = await widget.client.getLogLevel();
    final wasTrace = initialLevel == DaemonLogLevel.trace;

    var levelChanged = false;
    var persistenceEnabled = false;
    var cpuProfileStarted = false;

    try {
      if (!wasTrace) {
        await widget.client.setLogLevel(DaemonLogLevel.trace);
        levelChanged = true;
      }

      try {
        await widget.client.bringDown();
      } catch (_) {
        // Already down is fine; daemon returns OK either way.
      }
      await Future<void>.delayed(const Duration(seconds: 1));

      try {
        await widget.client.setSyncResponsePersistence(true);
        persistenceEnabled = true;
      } catch (_) {
        // Persistence is best-effort — the bundle still works without it.
      }

      await widget.client.bringUp();
      await Future<void>.delayed(const Duration(seconds: 3));

      try {
        await widget.client.startCpuProfile();
        cpuProfileStarted = true;
      } catch (_) {
        // CPU profiling is optional.
      }

      await _trackProgress(duration);

      if (cpuProfileStarted) {
        try {
          await widget.client.stopCpuProfile();
        } catch (_) {}
      }

      if (!mounted) {
        return const DebugBundleResult(path: '');
      }
      setState(() {
        _status = 'Creating debug bundle with collected logs...';
        _progress = null;
      });

      return await widget.client.debugBundle(
        anonymize: _anonymize,
        systemInfo: _systemInfo,
        uploadUrl: uploadUrl,
      );
    } finally {
      if (levelChanged) {
        try {
          await widget.client.setLogLevel(initialLevel);
        } catch (_) {}
      }
      if (persistenceEnabled) {
        try {
          await widget.client.setSyncResponsePersistence(false);
        } catch (_) {}
      }
    }
  }

  Future<void> _trackProgress(Duration total) async {
    final start = DateTime.now();
    final end = start.add(total);
    setState(() {
      _progress = 0;
      _status = 'Running with trace logs... ${_formatRemaining(total)} remaining';
    });

    while (DateTime.now().isBefore(end)) {
      await Future<void>.delayed(const Duration(milliseconds: 500));
      if (!mounted) {
        return;
      }
      final elapsed = DateTime.now().difference(start);
      final fraction = (elapsed.inMilliseconds / total.inMilliseconds).clamp(
        0.0,
        1.0,
      );
      final remaining = end.difference(DateTime.now());
      setState(() {
        _progress = fraction;
        _status =
            'Running with trace logs... ${_formatRemaining(remaining < Duration.zero ? Duration.zero : remaining)} remaining';
      });
    }
  }

  String _formatRemaining(Duration d) {
    final hours = d.inHours.toString().padLeft(2, '0');
    final minutes = (d.inMinutes % 60).toString().padLeft(2, '0');
    final seconds = (d.inSeconds % 60).toString().padLeft(2, '0');
    return '$hours:$minutes:$seconds';
  }

  Future<void> _showResultDialog(DebugBundleResult result) async {
    if (!mounted) {
      return;
    }
    await showDialog<void>(
      context: context,
      builder: (context) => _DebugResultDialog(result: result),
    );
  }
}

class _DebugResultDialog extends StatelessWidget {
  const _DebugResultDialog({required this.result});

  final DebugBundleResult result;

  @override
  Widget build(BuildContext context) {
    final folder = _parentFolder(result.path);

    String title;
    Widget body;
    if (result.uploadFailed) {
      title = 'Upload Failed';
      body = Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('Bundle upload failed:\n${result.uploadFailureReason}'),
          const SizedBox(height: 12),
          SelectableText('Local copy: ${result.path}'),
        ],
      );
    } else if (result.uploaded) {
      title = 'Upload Successful';
      body = Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('Bundle uploaded successfully.'),
          const SizedBox(height: 12),
          const Text('Upload key:'),
          SelectableText(result.uploadedKey),
          const SizedBox(height: 12),
          SelectableText('Local copy: ${result.path}'),
        ],
      );
    } else {
      title = 'Debug Bundle Created';
      body = Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('Bundle created locally at:\n${result.path}'),
          const SizedBox(height: 8),
          const Text(
            'Administrator privileges may be required to access the file.',
            style: TextStyle(fontStyle: FontStyle.italic),
          ),
        ],
      );
    }

    return AlertDialog(
      title: Text(title),
      content: SingleChildScrollView(child: body),
      actions: [
        if (result.uploaded)
          TextButton.icon(
            onPressed: () async {
              await Clipboard.setData(
                ClipboardData(text: result.uploadedKey),
              );
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Upload key copied')),
                );
              }
            },
            icon: const Icon(Icons.copy),
            label: const Text('Copy key'),
          ),
        TextButton.icon(
          onPressed: result.path.isEmpty
              ? null
              : () => openExternalUrl(result.path),
          icon: const Icon(Icons.description_outlined),
          label: const Text('Open file'),
        ),
        TextButton.icon(
          onPressed: folder.isEmpty ? null : () => openExternalUrl(folder),
          icon: const Icon(Icons.folder_open),
          label: const Text('Open folder'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }

  String _parentFolder(String path) {
    if (path.isEmpty) {
      return '';
    }
    final lastSlash = path.lastIndexOf(RegExp(r'[/\\]'));
    return lastSlash <= 0 ? '' : path.substring(0, lastSlash);
  }
}
