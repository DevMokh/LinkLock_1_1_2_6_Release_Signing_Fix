import 'package:flutter/material.dart';

import '../clipboard_guard.dart';
import '../device_key_store.dart';
import '../recovery_code.dart';

Future<void> showRecoverySheet(BuildContext context) {
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    builder: (_) => const _RecoverySheet(),
  );
}

class _RecoverySheet extends StatefulWidget {
  const _RecoverySheet();

  @override
  State<_RecoverySheet> createState() => _RecoverySheetState();
}

class _RecoverySheetState extends State<_RecoverySheet> {
  final _store = DeviceKeyStore();
  final _input = TextEditingController();
  String? _code;

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  void _toast(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _show() async {
    try {
      final key = await _store.getOrCreateKey();
      if (!mounted) return;
      setState(() => _code = RecoveryCode.encode(key));
    } catch (_) {
      _toast('مفتاح الجهاز الحالي غير صالح. أدخل مفتاح الاسترجاع في الحقل بالأسفل.');
    }
  }

  Future<void> _copy() async {
    final code = _code;
    if (code == null) return;
    await ClipboardGuard.copy(code);
    _toast('اتنسخ (هيتمسح من الحافظة بعد 30 ثانية). اكتبه على ورقة دلوقتي');
  }

  Future<void> _restore() async {
    final key = RecoveryCode.decode(_input.text);
    if (key == null) {
      _toast('المفتاح غلط أو فيه حرف ناقص');
      return;
    }
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('استرجاع المفتاح؟'),
        content: const Text(
          'هيحل محل مفتاح الجهاز الحالي. أي رابط متقفل بالمفتاح '
          'الحالي مش هيتفتح تاني.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('إلغاء'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('استرجع'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await _store.importKey(key);
    if (!mounted) return;
    _input.clear();
    setState(() => _code = null);
    _toast('اتسترجع المفتاح');
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: EdgeInsets.fromLTRB(
        16,
        16,
        16,
        16 + MediaQuery.of(context).viewInsets.bottom,
      ),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('مفتاح الاسترجاع', style: theme.textTheme.titleLarge),
            const SizedBox(height: 8),
            const Text(
              'اللي معاه المفتاح ده يفتح كل روابطك المقفولة، واللي مش معاه '
              'مايقدرش. اكتبه على ورقة واحفظها في مكان آمن. لو ضاع المفتاح '
              'والجهاز، الروابط ضايعة للأبد (زي محفظة البتكوين). ماتصوّرهوش '
              'وماتبعتوش لحد.',
            ),
            const SizedBox(height: 10),
            DecoratedBox(
              decoration: BoxDecoration(
                color: theme.colorScheme.errorContainer,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Text(
                  'مهم: الـ55 حرف دول هما المفتاح السري نفسه بصيغة قابلة للكتابة، مش PIN إضافي. أي حد يشوفهم يقدر يفتح الروابط المحمية بمفتاح الجهاز.',
                  style: TextStyle(color: theme.colorScheme.onErrorContainer),
                ),
              ),
            ),
            const SizedBox(height: 12),
            if (_code == null)
              FilledButton.icon(
                onPressed: _show,
                icon: const Icon(Icons.visibility_outlined),
                label: const Text('اعرض مفتاح الاسترجاع'),
              )
            else ...[
              Directionality(
                textDirection: TextDirection.ltr,
                child: SelectableText(
                  _code!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 15),
                ),
              ),
              const SizedBox(height: 8),
              FilledButton.tonalIcon(
                onPressed: _copy,
                icon: const Icon(Icons.copy_rounded),
                label: const Text('نسخ'),
              ),
            ],
            const Divider(height: 32),
            Text('استرجاع على جهاز جديد', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            TextField(
              controller: _input,
              autocorrect: false,
              enableSuggestions: false,
              textDirection: TextDirection.ltr,
              decoration: const InputDecoration(
                labelText: 'الصق مفتاح الاسترجاع',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            FilledButton.tonal(
              onPressed: _restore,
              child: const Text('استرجع المفتاح'),
            ),
          ],
        ),
      ),
    );
  }
}
