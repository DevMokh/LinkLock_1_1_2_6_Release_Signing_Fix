import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:share_plus/share_plus.dart';

import '../clipboard_guard.dart';
import '../crypto_service.dart';
import '../device_key_store.dart';
import '../services/server_share_service.dart';

class EncryptTab extends StatefulWidget {
  const EncryptTab({super.key});

  @override
  State<EncryptTab> createState() => _EncryptTabState();
}

class _EncryptTabState extends State<EncryptTab>
    with AutomaticKeepAliveClientMixin {
  final _formKey = GlobalKey<FormState>();
  final _link = TextEditingController();
  final _crypto = LinkCrypto(deviceKeyProvider: DeviceKeyStore().getOrCreateKey);
  final _serverShareService = ServerShareService();

  bool _deviceOnly = true;
  bool _usePass = false;
  final _pass = TextEditingController();
  bool _resultPass = false;
  bool _busy = false;
  String? _result;
  bool _resultDeviceOnly = false;
  bool _sharingOnServer = false;
  String? _revokingShareId;
  List<ServerShare> _webShares = <ServerShare>[];

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    _restoreWebShares();
  }

  Future<void> _restoreWebShares() async {
    if (!_serverShareService.isConfigured) return;
    try {
      final saved = await _serverShareService.loadShares();
      if (mounted) setState(() => _webShares = saved);
    } on ServerShareException catch (error) {
      _toast(error.message);
    }
  }

  @override
  void dispose() {
    _link.dispose();
    _pass.dispose();
    super.dispose();
  }

  void _toast(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim();
    if (text != null && text.isNotEmpty) {
      setState(() => _link.text = text);
    }
  }

  Future<void> _encrypt() async {
    if (!_formKey.currentState!.validate()) return;
    FocusScope.of(context).unfocus();
    final deviceOnly = _deviceOnly;
    final pass = _usePass ? _pass.text : null;
    setState(() {
      _busy = true;
      _result = null;
    });
    // Let the spinner draw before the (deliberately slow) key stretching.
    await Future<void>.delayed(const Duration(milliseconds: 60));
    try {
      final token = await _crypto.encrypt(
        _link.text,
        deviceOnly: deviceOnly,
        passphrase: pass,
      );
      if (!mounted) return;
      setState(() {
        _result = token;
        _resultDeviceOnly = deviceOnly;
        _resultPass = pass != null;
      });
    } on LinkCryptoException catch (e) {
      _toast(e.message);
    } catch (_) {
      _toast('حصل خطأ غير متوقع أثناء التشفير');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copy() async {
    final result = _result;
    if (result == null) return;
    await ClipboardGuard.copy(result);
    _toast('اتنسخ النص المشفّر (هيتمسح من الحافظة بعد 30 ثانية)');
  }

  Future<void> _createWebShare() async {
    if (_link.text.trim().isEmpty) {
      _toast('اكتب الرابط الأول');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      _sharingOnServer = true;
    });
    try {
      final share = await _serverShareService.createShare(_link.text);
      if (!mounted) return;
      setState(() => _webShares = [share, ..._webShares.where((item) => item.id != share.id)].take(100).toList());
      _toast(share.revokeTokenSaved
          ? 'اتعمل رابط ويب. الرابط صالح لحد ${share.expiresAt.toLocal()}'
          : 'اتعمل الرابط، لكن تعذر حفظ رمز الإلغاء. تقدر تلغيه قبل إغلاق التطبيق.');
    } on ServerShareException catch (e) {
      _toast(e.message);
    } catch (_) {
      _toast('حصل خطأ غير متوقع أثناء إنشاء رابط الويب');
    } finally {
      if (mounted) setState(() => _sharingOnServer = false);
    }
  }

  Future<void> _copyWebShare(ServerShare share) async {
    await ClipboardGuard.copy(share.url);
    _toast('اتنسخ رابط المشاركة');
  }

  Future<void> _shareWebShare(ServerShare share) async {
    await Share.share(share.url);
  }

  Future<void> _revokeWebShare(ServerShare share) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('إلغاء رابط المشاركة؟'),
        content: const Text('أي شخص معاه الرابط مش هيقدر يفتحه بعد الإلغاء.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('رجوع'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('إلغاء الرابط'),
          ),
        ],
      ),
    );
    if (!mounted || confirmed != true) return;
    setState(() => _revokingShareId = share.id);
    try {
      await _serverShareService.revokeShare(share);
      if (!mounted) return;
      setState(() => _webShares.removeWhere((item) => item.id == share.id));
      _toast('اتلغى رابط المشاركة');
    } on ServerShareException catch (e) {
      _toast(e.message);
    } catch (_) {
      _toast('مقدرتش ألغي رابط المشاركة');
    } finally {
      if (mounted) setState(() => _revokingShareId = null);
    }
  }

  Future<void> _share() async {
    final result = _result;
    if (result == null) return;
    await Share.share(result);
  }

  String get _resultNote {
    if (_resultPass && _resultDeviceOnly) {
      return 'محتاج كلمة السر ومفتاح جهازك (أو مفتاح الاسترجاع) مع بعض '
          'عشان يتفتح.';
    }
    if (_resultPass) {
      return 'بيتفتح على أي جهاز عليه التطبيق، بس لازم كلمة السر. لو كلمة '
          'السر ضعيفة ممكن حد يخمّنها.';
    }
    if (_resultDeviceOnly) {
      return 'اتشفّر بمفتاح محفوظ في الجهاز ده. لو مسحت التطبيق أو غيّرت '
          'الجهاز من غير مفتاح الاسترجاع مش هتقدر تفتحه.';
    }
    return 'المفتاح جوه النص نفسه، فبيتفتح على أي جهاز عليه التطبيق. ده '
        'تمويه مش حماية.';
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextFormField(
                controller: _link,
                keyboardType: TextInputType.url,
                autocorrect: false,
                textInputAction: TextInputAction.done,
                decoration: InputDecoration(
                  labelText: 'الرابط',
                  hintText: 'https://example.com/...',
                  border: const OutlineInputBorder(),
                  prefixIcon: const Icon(Icons.link_rounded),
                  suffixIcon: IconButton(
                    tooltip: 'لصق',
                    icon: const Icon(Icons.content_paste_rounded),
                    onPressed: _paste,
                  ),
                ),
                validator: (v) => (v == null || v.trim().isEmpty)
                    ? 'اكتب الرابط الأول'
                    : null,
              ),
              const SizedBox(height: 8),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: _deviceOnly,
                onChanged:
                    _busy ? null : (v) => setState(() => _deviceOnly = v),
                title: const Text('اقفله على الجهاز ده بس'),
                subtitle: Text(
                  _deviceOnly
                      ? 'محدش يقدر يفتحه غير اللي معاه مفتاحك (الجهاز ده أو مفتاح الاسترجاع).'
                      : 'تمويه للمشاركة: أي حد معاه النص والتطبيق يقدر يفتحه. '
                          'شغّل الخيار ده لو عايز حماية حقيقية.',
                ),
              ),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: _usePass,
                onChanged: (_busy || _sharingOnServer)
                    ? null
                    : (v) => setState(() => _usePass = v),
                title: const Text('أضف كلمة سر'),
                subtitle: const Text(
                  'طبقة تانية: لازم كلمة السر كمان عشان يتفتح. لو نسيتها '
                  'مفيش رجوع.',
                ),
              ),
              if (_usePass)
                TextFormField(
                  controller: _pass,
                  obscureText: true,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(
                    labelText: 'كلمة السر',
                    helperText: '10 حروف على الأقل. الأقوى: 4 كلمات عشوائية أو أكتر.',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.password_rounded),
                  ),
                  validator: (v) => (_usePass && (v == null || v.length < 10))
                      ? 'كلمة السر لازم تكون 10 حروف على الأقل'
                      : null,
                ),
              const SizedBox(height: 8),
              FilledButton.icon(
                onPressed: (_busy || _sharingOnServer) ? null : _encrypt,
                icon: _busy
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.lock_rounded),
                label: Text(_busy ? 'بيشفّر...' : 'شفّر الرابط'),
              ),
              const SizedBox(height: 10),
              OutlinedButton.icon(
                onPressed: (_busy || _sharingOnServer) ? null : _createWebShare,
                icon: _sharingOnServer
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.public_rounded),
                label: Text(
                  _sharingOnServer ? 'بينشئ رابط الويب...' : 'إنشاء رابط ويب مباشر',
                ),
              ),
              const SizedBox(height: 6),
              Text(
                'رابط المشاركة نفسه يحتوي على بيانات الوجهة المشفّرة، وليس الرابط الأصلي كنص مكشوف. يفتح من أي متصفح، ويعرض اسم الموقع قبل المتابعة ثم يفتح العنوان الأصلي بشكل طبيعي. يحتاج إعداد خادم LinkLock، '
                'والخادم يحتفظ بمفتاح التشفير. المدة الافتراضية 7 أيام. '
                'خيارات الجهاز وكلمة السر بالأعلى تخص تشفير LL3 المحلي فقط.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
        if (_webShares.isNotEmpty) ...[
          const SizedBox(height: 20),
          for (final share in _webShares) ...[
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text('رابط مشاركة ويب', style: theme.textTheme.titleSmall),
                    const SizedBox(height: 8),
                    Directionality(
                      textDirection: TextDirection.ltr,
                      child: SelectableText(
                        share.url,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text('ينتهي في: ${share.expiresAt.toLocal()}', style: theme.textTheme.bodySmall),
                    if (!share.revokeTokenSaved)
                      const Text('تحذير: رمز الإلغاء لم يُحفظ. انسخ الرابط الآن؛ لن يمكن إلغاءه من التطبيق بعد إغلاقه.'),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: FilledButton.tonalIcon(
                            onPressed: () => _copyWebShare(share),
                            icon: const Icon(Icons.copy_rounded),
                            label: const Text('نسخ'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: FilledButton.tonalIcon(
                            onPressed: () => _shareWebShare(share),
                            icon: const Icon(Icons.share_rounded),
                            label: const Text('مشاركة'),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    OutlinedButton.icon(
                      onPressed: _revokingShareId == share.id ? null : () => _revokeWebShare(share),
                      icon: _revokingShareId == share.id
                          ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                          : const Icon(Icons.link_off_rounded),
                      label: Text(_revokingShareId == share.id ? 'بيلغي الرابط...' : 'إلغاء رابط المشاركة'),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'الخادم يقدر يفك تشفير الوجهة، وبعد المتابعة هيظهر عنوان الموقع الأصلي. مفتاح التشفير مش موجود في رابط المشاركة.',
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ],
        if (_result != null) ...[
          const SizedBox(height: 24),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('النص المشفّر', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 8),
                  Directionality(
                    textDirection: TextDirection.ltr,
                    child: SelectableText(
                      _result!,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: FilledButton.tonalIcon(
                          onPressed: _copy,
                          icon: const Icon(Icons.copy_rounded),
                          label: const Text('نسخ'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: FilledButton.tonalIcon(
                          onPressed: _share,
                          icon: const Icon(Icons.share_rounded),
                          label: const Text('مشاركة'),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    _resultNote,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}
