import 'package:flutter_test/flutter_test.dart';
import 'package:netbird_flutter_ui/src/app_shell.dart';
import 'package:netbird_flutter_ui/src/daemon_client.dart';

void main() {
  testWidgets('renders the status shell', (tester) async {
    await tester.pumpWidget(
      NetBirdFlutterApp(
        client: FakeDaemonClient(daemonAddr: 'tcp://127.0.0.1:41731'),
      ),
    );

    await tester.pump();

    expect(find.text('Status'), findsWidgets);
    expect(find.text('Connect'), findsOneWidget);
    expect(find.text('Disconnect'), findsOneWidget);
  });
}
