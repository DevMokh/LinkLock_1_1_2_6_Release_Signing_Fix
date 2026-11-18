import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../strength_tester.dart';

class StrengthTab extends StatefulWidget {
  const StrengthTab({super.key});

  @override
  State<StrengthTab> createState() => _StrengthTabState();
}

class _StrengthTabState extends State<StrengthTab>
    with AutomaticKeepAliveClientMixin {
  final _link = TextEditingController(
    text: 'https://www.example.com/some/path?query=1&lang=ar',
  );
  final _tester = StrengthTester();

  bool _busy = false;
  ModeReport? _share;
  ModeReport? _device;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _link.dispose();
    super.dispose();
  }

  void _toast(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _run() async {
    final link = _link.text.trim();
    if (link.isEmpty) {
      _toast('اكتب الرابط الأول');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() => _busy = true);
    try {
      final share = await _tester.run(link, deviceOnly: false);
      final device = await _tester.run(link, deviceOnly: true);
      if (!mounted) return;
      setState(() {
        _share = share;
        _device = device;
      });
    } catch (_) {
      _toast('حصل خطأ أثناء الاختبار');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copySamples() async {
    final share = _share;
    final device = _device;
    if (share == null || device == null) return;
    final out = StringBuffer()
      ..writeln('# share = وضع المشاركة (المفتاح جوه النص)')
      ..writeln('# device = وضع الجهاز (مفتاح مؤقت للاختبار، مش مفتاحك الحقيقي)')
      ..writeln('# الرابط الأصلي: ${_link.text.trim()}');
    for (final t in share.tokens) {
      out.writeln('share,$t');
    }
    for (final t in device.tokens) {
      out.writeln('device,$t');
    }
    await Clipboard.setData(ClipboardData(text: out.toString()));
    _toast('اتنسخت ${share.tokens.length + device.tokens.length} عينة');
  }

  Widget _row(String label, String value, {bool? good}) {
    final scheme = Theme.of(context).colorScheme;
    final Color? color = good == null
        ? null
        : (good ? Colors.green.shade600 : scheme.error);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (good != null)
            Icon(
              good ? Icons.check_circle_outline : Icons.warning_amber_rounded,
              size: 18,
              color: color,
            )
          else
            const SizedBox(width: 18),
          const SizedBox(width: 8),
          Expanded(child: Text(label)),
          const SizedBox(width: 8),
          Text(
            value,
            style: TextStyle(fontWeight: FontWeight.w600, color: color),
          ),
        ],
      ),
    );
  }

  Widget _card(String title, ModeReport r) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Expanded(child: Text(title, style: theme.textTheme.titleMedium)),
                Chip(
                  label: Text(r.strong ? 'حماية حقيقية' : 'تمويه بس'),
                  backgroundColor: r.strong
                      ? Colors.green.shade100
                      : theme.colorScheme.errorContainer,
                ),
              ],
            ),
            const SizedBox(height: 8),
            _row('المفتاح جوه النص؟', r.keyInsideToken ? 'أيوه' : 'لأ',
                good: !r.keyInsideToken),
            _row('غريب معاه النص بس يفتحه؟', r.openedByStranger ? 'أيوه' : 'لأ',
                good: !r.openedByStranger),
            _row('تعديل بت واحد اتكشف', '${r.tamperRejected}/${r.tamperRuns}',
                good: r.tamperProof),
            _row('نصوص مختلفة (لنفس الرابط)', '${r.uniqueTokens}/${r.samples}',
                good: r.uniqueTokens == r.samples),
            _row('nonce مختلف', '${r.uniqueNonces}/${r.samples}',
                good: r.uniqueNonces == r.samples),
            _row('العشوائية (bit/byte)', r.entropy.toStringAsFixed(3),
                good: r.entropy > 7.5),
            _row('طول النص', '${r.tokenChars} حرف'),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);
    final share = _share;
    final device = _device;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TextField(
          controller: _link,
          keyboardType: TextInputType.url,
          autocorrect: false,
          textDirection: TextDirection.ltr,
          decoration: const InputDecoration(
            labelText: 'رابط الاختبار',
            border: OutlineInputBorder(),
            prefixIcon: Icon(Icons.link_rounded),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.icon(
          onPressed: _busy ? null : _run,
          icon: _busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.shield_outlined),
          label: Text(_busy ? 'بيختبر...' : 'شغّل الاختبار على الوضعين'),
        ),
        const SizedBox(height: 8),
        Text(
          'بيعمل 100 تشفير لكل وضع ويجرّب 100 تعديل. بيستخدم مفاتيح مؤقتة '
          'ومش بيلمس مفتاح جهازك الحقيقي.',
          style: theme.textTheme.bodySmall
              ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
        ),
        if (share != null && device != null) ...[
          const SizedBox(height: 16),
          _card('وضع المشاركة', share),
          const SizedBox(height: 8),
          _card('وضع الجهاز ده بس', device),
          const SizedBox(height: 12),
          FilledButton.tonalIcon(
            onPressed: _copySamples,
            icon: const Icon(Icons.copy_rounded),
            label: const Text('انسخ كل العينات لتطبيق التحليل'),
          ),
        ],
      ],
    );
  }
}
