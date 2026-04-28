import 'dart:io';

/// Opens a URL in the user's default browser. Returns false if the platform
/// helper exits non-zero or is missing. Mirrors the Go UI's `openURL` logic.
Future<bool> openExternalUrl(String url) async {
  try {
    final ProcessResult result;
    if (Platform.isMacOS) {
      result = await Process.run('open', [url]);
    } else if (Platform.isWindows) {
      result = await Process.run('rundll32', [
        'url.dll,FileProtocolHandler',
        url,
      ]);
    } else {
      result = await Process.run('xdg-open', [url]);
    }
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}
