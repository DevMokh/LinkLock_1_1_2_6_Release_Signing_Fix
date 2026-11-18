import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';

import 'ui/home_page.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const LinkLockApp());
}

class LinkLockApp extends StatefulWidget {
  const LinkLockApp({super.key});

  @override
  State<LinkLockApp> createState() => _LinkLockAppState();
}

class _LinkLockAppState extends State<LinkLockApp>
    with WidgetsBindingObserver {
  final LocalAuthentication _authentication = LocalAuthentication();
  bool _checking = true;
  bool _locked = true;
  bool _deviceAuthenticationAvailable = false;
  bool _authInProgress = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _authenticate());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused && _deviceAuthenticationAvailable) {
      if (mounted) setState(() => _locked = true);
    } else if (state == AppLifecycleState.resumed &&
        _deviceAuthenticationAvailable &&
        !_authInProgress) {
      _authenticate();
    }
  }

  Future<void> _authenticate() async {
    if (_authInProgress || !mounted) return;
    _authInProgress = true;
    setState(() {
      _checking = true;
      _error = null;
    });
    try {
      final supported = await _authentication.isDeviceSupported();
      if (!supported) {
        // Do not lock users out on devices without an enrolled system lock.
        if (mounted) {
          setState(() {
            _deviceAuthenticationAvailable = false;
            _locked = false;
            _checking = false;
          });
        }
        return;
      }
      _deviceAuthenticationAvailable = true;
      final authenticated = await _authentication.authenticate(
        localizedReason: 'افتح قفل LinkLock بالبصمة أو رمز قفل الجهاز',
        options: const AuthenticationOptions(
          biometricOnly: false,
          stickyAuth: true,
        ),
      );
      if (mounted) {
        setState(() {
          _locked = !authenticated;
          _checking = false;
          _error = authenticated ? null : 'لازم تأكد هويتك لفتح التطبيق.';
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _locked = true;
          _checking = false;
          _error = 'تعذر التحقق. استخدم البصمة أو رمز قفل الجهاز وحاول مرة أخرى.';
        });
      }
    } finally {
      _authInProgress = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF1E6F5C);
    return MaterialApp(
      title: 'قفل الروابط',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: seed),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: seed,
        brightness: Brightness.dark,
      ),
      builder: (context, child) => Directionality(
        textDirection: TextDirection.rtl,
        child: child ?? const SizedBox.shrink(),
      ),
      home: _checking || _locked
          ? _AppLockScreen(
              checking: _checking,
              error: _error,
              onUnlock: _authenticate,
            )
          : const HomePage(),
    );
  }
}

class _AppLockScreen extends StatelessWidget {
  const _AppLockScreen({
    required this.checking,
    required this.error,
    required this.onUnlock,
  });

  final bool checking;
  final String? error;
  final VoidCallback onUnlock;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.lock_outline_rounded, size: 56),
                const SizedBox(height: 16),
                Text('قفل LinkLock', style: theme.textTheme.headlineSmall),
                const SizedBox(height: 8),
                const Text('افتح التطبيق بالبصمة أو PIN أو كلمة مرور قفل الجهاز.'),
                if (checking) ...[
                  const SizedBox(height: 20),
                  const CircularProgressIndicator(),
                ] else ...[
                  if (error != null) ...[
                    const SizedBox(height: 12),
                    Text(error!, textAlign: TextAlign.center),
                  ],
                  const SizedBox(height: 20),
                  FilledButton.icon(
                    onPressed: onUnlock,
                    icon: const Icon(Icons.fingerprint_rounded),
                    label: const Text('فتح التطبيق'),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}