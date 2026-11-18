import 'dart:async';

import 'package:flutter/services.dart';

/// Copies text and wipes it from the clipboard after [clearAfter], so
/// secrets don't sit there for other apps to read.
class ClipboardGuard {
  static Timer? _timer;

  static Future<void> copy(
    String text, {
    Duration clearAfter = const Duration(seconds: 30),
  }) async {
    await Clipboard.setData(ClipboardData(text: text));
    _timer?.cancel();
    _timer = Timer(clearAfter, () async {
      try {
        final current = (await Clipboard.getData(Clipboard.kTextPlain))?.text;
        // Skip only if the user has since copied something else.
        if (current == null || current == text) {
          await Clipboard.setData(const ClipboardData(text: ''));
        }
      } catch (_) {}
    });
  }
}
