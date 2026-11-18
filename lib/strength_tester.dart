import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'crypto_service.dart';

/// Result of stress-testing one encryption mode.
class ModeReport {
  const ModeReport({
    required this.deviceOnly,
    required this.samples,
    required this.tokenChars,
    required this.uniqueTokens,
    required this.uniqueNonces,
    required this.tamperRuns,
    required this.tamperRejected,
    required this.keyInsideToken,
    required this.openedByStranger,
    required this.entropy,
    required this.tokens,
  });

  final bool deviceOnly;
  final int samples;

  /// Length (characters) of the first token, e.g. to compare the two modes.
  final int tokenChars;
  final int uniqueTokens;
  final int uniqueNonces;

  /// How many single-bit modifications were tried, and how many the
  /// decryption refused (all of them should be refused).
  final int tamperRuns;
  final int tamperRejected;

  /// True when the secret key travels inside the token itself.
  final bool keyInsideToken;

  /// True when a stranger (different device key, token only) got the link back.
  final bool openedByStranger;

  /// Shannon entropy of the token bytes after the 2-byte header, in bits per
  /// byte (8.0 is perfectly random).
  final double entropy;
  final List<String> tokens;

  bool get noRepeats => uniqueTokens == samples && uniqueNonces == samples;
  bool get tamperProof => tamperRejected == tamperRuns;

  /// Real protection: the token alone is useless without a secret that never
  /// leaves the device, nothing repeats, and any edit is detected.
  bool get strong =>
      !keyInsideToken && !openedByStranger && noRepeats && tamperProof;
}

/// Self-test harness for [LinkCrypto]. It uses throwaway device keys, so it
/// never touches the real key stored on this device.
class StrengthTester {
  StrengthTester({Random? random}) : _random = random ?? Random.secure();

  final Random _random;

  List<int> _newKey() => List<int>.generate(32, (_) => _random.nextInt(256));

  static Uint8List _decode(String token) {
    final body = token.substring(LinkCrypto.prefix.length);
    return base64Url.decode(base64Url.normalize(body));
  }

  static String _encode(Uint8List bytes) =>
      LinkCrypto.prefix + base64Url.encode(bytes).replaceAll('=', '');

  Future<ModeReport> run(
    String link, {
    required bool deviceOnly,
    int samples = 100,
    int tamperRuns = 100,
  }) async {
    if (samples < 1 || samples > 1000) {
      throw RangeError.range(samples, 1, 1000, 'samples');
    }
    if (tamperRuns < 1 || tamperRuns > 1000) {
      throw RangeError.range(tamperRuns, 1, 1000, 'tamperRuns');
    }
    if (link.trim().isEmpty) {
      throw ArgumentError.value(link, 'link', 'must not be empty');
    }
    final ownerKey = _newKey();
    final strangerKey = _newKey();
    final owner = LinkCrypto(
      deviceKeyProvider: () async => ownerKey,
      random: _random,
    );
    final stranger = LinkCrypto(
      deviceKeyProvider: () async => strangerKey,
      random: _random,
    );

    final tokens = <String>[];
    for (var i = 0; i < samples; i++) {
      tokens.add(await owner.encrypt(link, deviceOnly: deviceOnly));
    }

    final decoded = tokens.map(_decode).toList();

    // Layout: [version, flags, (16-byte key in shareable mode), nonce(12), ...]
    final first = decoded.first;
    final keyInsideToken = (first[1] & 1) == 0;
    final nonceOffset = keyInsideToken ? 18 : 2;
    final nonces = decoded
        .map((b) => base64Encode(b.sublist(nonceOffset, nonceOffset + 12)))
        .toSet();

    // Edit one random bit anywhere in a token; decryption must refuse it.
    var rejected = 0;
    for (var i = 0; i < tamperRuns; i++) {
      final bytes = Uint8List.fromList(decoded[i % decoded.length]);
      bytes[_random.nextInt(bytes.length)] ^= 1 << _random.nextInt(8);
      try {
        await owner.decrypt(_encode(bytes));
      } catch (_) {
        rejected++;
      }
    }

    // A stranger with only the token and a different device key.
    var opened = false;
    try {
      opened = (await stranger.decrypt(tokens.first)) == link.trim();
    } catch (_) {
      opened = false;
    }

    return ModeReport(
      deviceOnly: deviceOnly,
      samples: samples,
      tokenChars: tokens.first.length,
      uniqueTokens: tokens.toSet().length,
      uniqueNonces: nonces.length,
      tamperRuns: tamperRuns,
      tamperRejected: rejected,
      keyInsideToken: keyInsideToken,
      openedByStranger: opened,
      entropy: _entropy(decoded),
      tokens: tokens,
    );
  }

  static double _entropy(List<Uint8List> all) {
    final counts = List<int>.filled(256, 0);
    var total = 0;
    for (final bytes in all) {
      for (var i = 2; i < bytes.length; i++) {
        counts[bytes[i]]++;
        total++;
      }
    }
    if (total == 0) return 0;
    var h = 0.0;
    for (final c in counts) {
      if (c == 0) continue;
      final p = c / total;
      h -= p * (log(p) / ln2);
    }
    return h;
  }
}
