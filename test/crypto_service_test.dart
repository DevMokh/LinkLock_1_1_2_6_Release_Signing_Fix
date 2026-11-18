import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklock/crypto_service.dart';

void main() {
  final deviceA = List<int>.generate(32, (i) => i);
  final deviceB = List<int>.generate(32, (i) => 255 - i);

  LinkCrypto cryptoFor(List<int> deviceKey) =>
      LinkCrypto(deviceKeyProvider: () async => deviceKey);

  final crypto = cryptoFor(deviceA);

  group('shareable mode (key inside the token)', () {
    test('round trip returns the original link', () async {
      const link = 'https://example.com/path?a=1&b=two#frag';
      final token = await crypto.encrypt(link);

      expect(token.startsWith(LinkCrypto.prefix), isTrue);
      expect(token.contains('example.com'), isFalse);
      expect(await crypto.decrypt(token), link);
    });

    test('opens on another device', () async {
      final token = await crypto.encrypt('https://a.io/x');
      expect(await cryptoFor(deviceB).decrypt(token), 'https://a.io/x');
    });

    test('handles Arabic text and emoji', () async {
      const link = 'https://مثال.com/صفحة?q=تجربة 🔒';
      final token = await crypto.encrypt(link);
      expect(await crypto.decrypt(token), link);
    });

    test('rejects invisible Unicode format characters instead of trimming them', () async {
      for (final link in [
        'https://exa\u2060mple.com/',
        'https://example.com/\u200Bhidden',
        'https://example.com/\u202Etxt.exe',
      ]) {
        await expectLater(
          crypto.encrypt(link),
          throwsA(isA<LinkCryptoException>()),
        );
      }
    });

    test('rejects hidden Unicode characters even inside an authenticated token', () async {
      const unsafeUrl = 'https://exa\u2060mple.com/hidden';
      final key = List<int>.generate(16, (i) => i + 1);
      final header = Uint8List.fromList([3, 0, ...key]);
      final box = await AesGcm.with128bits().encrypt(
        utf8.encode(unsafeUrl),
        secretKey: SecretKey(key),
        nonce: List<int>.generate(12, (i) => i + 20),
        aad: header,
      );
      final bytes = BytesBuilder(copy: false)
        ..add(header)
        ..add(box.concatenation());
      final token = LinkCrypto.prefix +
          base64Url.encode(bytes.takeBytes()).replaceAll('=', '');

      await expectLater(
        crypto.decrypt(token),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('enforces the URL limit in UTF-8 bytes', () async {
      final overLimit = 'https://a.io/${'é' * 1100}';
      await expectLater(
        crypto.encrypt(overLimit),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('trims the link before encrypting', () async {
      final token = await crypto.encrypt('  https://a.io  \n');
      expect(await crypto.decrypt(token), 'https://a.io');
    });

    test('same link gives a different token every time', () async {
      final a = await crypto.encrypt('https://a.io');
      final b = await crypto.encrypt('https://a.io');
      expect(a, isNot(equals(b)));
    });

    test('tampered token is rejected', () async {
      final token = await crypto.encrypt('https://a.io/secret');
      final mid = token.length ~/ 2;
      final tampered = token.substring(0, mid) +
          (token[mid] == 'A' ? 'B' : 'A') +
          token.substring(mid + 1);

      await expectLater(
        crypto.decrypt(tampered),
        throwsA(isA<LinkCryptoException>()),
      );
    });
  });

  group('device-only mode (key stays on the device)', () {
    test('round trip on the same device', () async {
      final token = await crypto.encrypt(
        'https://a.io/private',
        deviceOnly: true,
      );
      expect(await crypto.decrypt(token), 'https://a.io/private');
    });

    test('is rejected on a different device (e.g. after key rotation)',
        () async {
      final token = await crypto.encrypt(
        'https://a.io/private',
        deviceOnly: true,
      );
      await expectLater(
        cryptoFor(deviceB).decrypt(token),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('token is shorter than a shareable token of the same link',
        () async {
      final shareable = await crypto.encrypt('https://a.io');
      final device = await crypto.encrypt('https://a.io', deviceOnly: true);
      expect(device.length, lessThan(shareable.length));
    });

    test('fails cleanly when the device key is unavailable', () async {
      final broken = LinkCrypto(
        deviceKeyProvider: () async => throw StateError('no keystore'),
      );
      await expectLater(
        broken.encrypt('https://a.io', deviceOnly: true),
        throwsA(isA<LinkCryptoException>()),
      );
    });
  });

  group('token size', () {
    test('a repetitive link compresses into a visibly shorter token',
        () async {
      final rand = Random(42); // fixed seed: reproducible, not repetitive
      final repetitive = 'https://example.com/${'a' * 200}';
      final notRepetitive = 'https://example.com/${List.generate(
        200,
        (_) => String.fromCharCode(97 + rand.nextInt(26)),
      ).join()}';

      final tokenRepetitive = await crypto.encrypt(repetitive);
      final tokenNotRepetitive = await crypto.encrypt(notRepetitive);

      // Same input length either way; only the repetitive one should
      // compress away almost entirely.
      expect(
        tokenRepetitive.length,
        lessThan((tokenNotRepetitive.length * 0.7).round()),
      );
    });

    test('very short links still round-trip (compression skipped, not forced)',
        () async {
      final token = await crypto.encrypt('https://a.io');
      expect(await crypto.decrypt(token), 'https://a.io');
    });
  });

  group('input handling', () {
    test('token with whitespace and line breaks still decrypts', () async {
      final token = await crypto.encrypt('https://a.io');
      final wrapped = '${token.substring(0, 20)}\n ${token.substring(20)} ';
      expect(await crypto.decrypt(wrapped), 'https://a.io');
    });

    test('garbage and truncated input are rejected', () async {
      final token = await crypto.encrypt('https://a.io');
      for (final bad in ['hello', 'LL3.', 'LL3.@@@@', token.substring(0, 30)]) {
        await expectLater(
          crypto.decrypt(bad),
          throwsA(isA<LinkCryptoException>()),
          reason: 'input: $bad',
        );
      }
    });

    test('empty link is rejected', () async {
      await expectLater(
        crypto.encrypt('   '),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('rejects a token from the previous format version', () async {
      // LL2 tokens (the password-less v2 format from before this round of
      // changes) are no longer accepted.
      const oldToken = 'LL2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      await expectLater(
        crypto.decrypt(oldToken),
        throwsA(isA<LinkCryptoException>()),
      );
    });
  });

  group('input and format hardening', () {
    test('rejects non-http schemes and malformed URL input', () async {
      for (final value in ['javascript:alert(1)', 'file:///tmp/a', 'not a url']) {
        await expectLater(
          crypto.encrypt(value),
          throwsA(isA<LinkCryptoException>()),
          reason: value,
        );
      }
    });

    test('rejects unsupported flag bits before attempting decryption', () async {
      final token = await crypto.encrypt('https://example.com');
      final bytes = base64Url.decode(
        base64Url.normalize(token.substring(LinkCrypto.prefix.length)),
      );
      bytes[1] |= 0x80;
      final altered = LinkCrypto.prefix +
          base64Url.encode(bytes).replaceAll('=', '');
      await expectLater(
        crypto.decrypt(altered),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('rejects URL input beyond the documented byte limit', () async {
      final tooLong = 'https://example.com/${'a' * 2100}';
      await expectLater(
        crypto.encrypt(tooLong),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('bounds decompressed payload size', () async {
      final key = List<int>.generate(16, (i) => i + 1);
      final nonce = List<int>.generate(12, (i) => 200 + i);
      final header = Uint8List.fromList([3, 2, ...key]); // v3 + compressed
      final compressed = ZLibCodec(level: 9).encode(List<int>.filled(20000, 65));
      final box = await AesGcm.with128bits().encrypt(
        compressed,
        secretKey: SecretKey(key),
        nonce: nonce,
        aad: header,
      );
      final payload = BytesBuilder(copy: false)
        ..add(header)
        ..add(box.concatenation());
      final token = LinkCrypto.prefix +
          base64Url.encode(payload.takeBytes()).replaceAll('=', '');

      await expectLater(
        crypto.decrypt(token),
        throwsA(isA<LinkCryptoException>()),
      );
    });

    test('invalid UTF-8 plaintext is converted to LinkCryptoException', () async {
      final key = List<int>.generate(16, (i) => 90 + i);
      final nonce = List<int>.generate(12, (i) => 150 + i);
      final header = Uint8List.fromList([3, 0, ...key]); // v3, uncompressed
      final box = await AesGcm.with128bits().encrypt(
        [0xff],
        secretKey: SecretKey(key),
        nonce: nonce,
        aad: header,
      );
      final payload = BytesBuilder(copy: false)
        ..add(header)
        ..add(box.concatenation());
      final token = LinkCrypto.prefix +
          base64Url.encode(payload.takeBytes()).replaceAll('=', '');

      await expectLater(
        crypto.decrypt(token),
        throwsA(isA<LinkCryptoException>()),
      );
    });
  });

}
