import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

bool _containsUnsafeUnicode(String value) {
  // Unicode General_Category=Cf format controls.
  // Explicit ranges keep this check stable across Dart regexp implementations.
  const ranges = <(int, int)>[
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891),
    (0x08E2, 0x08E2), (0x180E, 0x180E), (0x200B, 0x200F),
    (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD),
    (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0001, 0xE0001), (0xE0020, 0xE007F),
  ];
  for (final rune in value.runes) {
    for (final range in ranges) {
      if (rune >= range.$1 && rune <= range.$2) return true;
    }
  }
  return false;
}

bool _containsControlCharacters(String value) => value.runes.any(
      (rune) => rune <= 0x1F || (rune >= 0x7F && rune <= 0x9F),
    );

class LinkCryptoException implements Exception {
  const LinkCryptoException(this.message);

  final String message;

  @override
  String toString() => 'LinkCryptoException: $message';
}

/// Returns the 32-byte key kept on this device (see DeviceKeyStore).
typedef DeviceKeyProvider = Future<List<int>> Function();

const int _maxUrlBytes = 2048;
const int _maxTokenCharacters = 16384;
const int _maxInflatedBytes = 16384;

class _BoundedByteSink implements Sink<List<int>> {
  final BytesBuilder _builder = BytesBuilder(copy: false);
  int _length = 0;

  @override
  void add(List<int> chunk) {
    _length += chunk.length;
    if (_length > _maxInflatedBytes) {
      throw const FormatException('Decompressed data exceeds the allowed size');
    }
    _builder.add(chunk);
  }

  @override
  void close() {}

  Uint8List takeBytes() => _builder.takeBytes();
}

/// Link encryption with an optional passphrase. AES-GCM in two modes:
///
/// * Shareable (default): a fresh random key is generated per link and
///   stored inside the token itself, using AES-128. It opens on any device
///   that has the app. Putting the key in the token means this is
///   obfuscation, not secrecy, no matter how big the key is — so the token
///   uses the smaller, shorter key rather than paying for strength that
///   can't matter here.
/// * Device-only: the key lives in the device's secure storage and never
///   leaves it, using AES-256 for a real security margin. The token opens
///   only on this device.
///
/// Before encrypting, the link is deflate-compressed when that actually
/// makes it smaller (most real URLs: repeated "https://", "www.", common
/// words); otherwise the raw bytes are used as-is, so short or already-dense
/// links never get padded out.
///
/// Token = `LL3.` + base64url(bytes) without padding, where bytes are:
///   [0]      format version (3)
///   [1]      flags bitmask: bit0 = device-only mode, bit1 = compressed,
///                    bit2 = passphrase (a 16-byte Argon2id salt replaces the key)
///   [2..]    the key (16 or 32 bytes), present only in shareable mode
///   then     AES-GCM nonce (12 bytes), ciphertext, 16-byte tag
///
/// Everything before the nonce (version, flags, and the key when present) is
/// authenticated as AAD.
class LinkCrypto {
  LinkCrypto({
    required DeviceKeyProvider deviceKeyProvider,
    Random? random,
    Argon2id? kdf,
  })  : _deviceKeyProvider = deviceKeyProvider,
        _random = random ?? Random.secure(),
        _kdf = kdf ?? defaultKdf;

  /// Argon2id settings (OWASP minimum: 19 MiB, 2 passes). They are part of
  /// the token format, so changing them means a new format version.
  static Argon2id get defaultKdf => Argon2id(
        parallelism: 1,
        memory: 19456,
        iterations: 2,
        hashLength: 32,
      );

  static const String prefix = 'LL3.';

  static const int _version = 3;
  static const int _flagDeviceOnly = 1 << 0;
  static const int _flagCompressed = 1 << 1;
  static const int _flagPassphrase = 1 << 2;
  static const int _saltLength = 16;

  static const int _embeddedKeyLength = 16; // AES-128: travels with the token anyway.
  static const int _deviceKeyLength = 32; // AES-256: the real secrecy boundary.
  static const int _nonceLength = 12;
  static const int _macLength = 16;
  static const int _headerLength = 2; // version + flags; key bytes (if any) follow.

  final DeviceKeyProvider _deviceKeyProvider;
  final Argon2id _kdf;
  final Random _random;
  final AesGcm _cipher128 = AesGcm.with128bits();
  final AesGcm _cipher256 = AesGcm.with256bits();

  Future<String> encrypt(
    String link, {
    bool deviceOnly = false,
    String? passphrase,
  }) async {
    if (_containsUnsafeUnicode(link)) {
      throw const LinkCryptoException('الرابط يحتوي على حروف Unicode مخفية');
    }
    final text = link.trim();
    if (_containsControlCharacters(text)) {
      throw const LinkCryptoException('الرابط يحتوي على محارف تحكم غير مسموح بها');
    }
    if (text.length > _maxUrlBytes) {
      throw const LinkCryptoException('الرابط أطول من الحد المسموح (2048 بايت)');
    }
    if (text.isEmpty) {
      throw const LinkCryptoException('اكتب الرابط الأول');
    }
    final parsed = Uri.tryParse(text);
    if (parsed == null ||
        (parsed.scheme != 'https' && parsed.scheme != 'http') ||
        parsed.host.isEmpty ||
        parsed.userInfo.isNotEmpty) {
      throw const LinkCryptoException('اكتب رابطًا صحيحًا يبدأ بـ http أو https');
    }

    final rawBytes = Uint8List.fromList(utf8.encode(text));
    if (rawBytes.length > _maxUrlBytes) {
      throw const LinkCryptoException('الرابط أطول من الحد المسموح (2048 بايت)');
    }
    final (payload, compressed) = _maybeCompress(rawBytes);

    final pass = passphrase ?? '';
    int flags = compressed ? _flagCompressed : 0;
    Uint8List extra = Uint8List(0); // embedded key, or Argon2id salt
    final List<int> key;
    final AesGcm cipher;

    if (pass.isNotEmpty) {
      flags |= _flagPassphrase;
      if (deviceOnly) flags |= _flagDeviceOnly;
      extra = _randomBytes(_saltLength);
      key = await _passphraseKey(pass, extra, deviceOnly: deviceOnly);
      cipher = _cipher256;
    } else if (deviceOnly) {
      flags |= _flagDeviceOnly;
      key = await _loadDeviceKey();
      cipher = _cipher256;
    } else {
      extra = _randomBytes(_embeddedKeyLength);
      key = extra;
      cipher = _cipher128;
    }

    final header = Uint8List.fromList([_version, flags, ...extra]);

    final box = await cipher.encrypt(
      payload,
      secretKey: SecretKey(key),
      nonce: _randomBytes(_nonceLength),
      aad: header,
    );

    // box.concatenation() = nonce + ciphertext + tag
    final out = BytesBuilder(copy: false)
      ..add(header)
      ..add(box.concatenation());
    return prefix + base64Url.encode(out.toBytes()).replaceAll('=', '');
  }

  Future<String> decrypt(String token, {String? passphrase}) async {
    if (token.length > _maxTokenCharacters * 2) {
      throw const LinkCryptoException('النص المشفّر أكبر من الحد المسموح');
    }
    final compact = token.replaceAll(RegExp(r'\s+'), '');
    if (compact.length > _maxTokenCharacters) {
      throw const LinkCryptoException('النص المشفّر أكبر من الحد المسموح');
    }
    if (!compact.startsWith(prefix)) {
      throw const LinkCryptoException('ده مش نص مشفّر بالتطبيق ده');
    }

    Uint8List data;
    try {
      data = base64Url.decode(
        base64Url.normalize(compact.substring(prefix.length)),
      );
    } on FormatException {
      throw const LinkCryptoException('النص المشفّر ناقص أو متعدّل');
    }

    if (data.length < _headerLength + _nonceLength + _macLength) {
      throw const LinkCryptoException('النص المشفّر ناقص أو متعدّل');
    }
    if (data[0] != _version) {
      throw const LinkCryptoException('إصدار التشفير ده مش مدعوم');
    }

    final flags = data[1];
    const supportedFlags = _flagDeviceOnly | _flagCompressed | _flagPassphrase;
    if ((flags & ~supportedFlags) != 0) {
      throw const LinkCryptoException('علامات التشفير غير مدعومة');
    }
    final deviceOnly = flags & _flagDeviceOnly != 0;
    final compressed = flags & _flagCompressed != 0;
    final usesPassphrase = flags & _flagPassphrase != 0;

    final List<int> key;
    final AesGcm cipher;
    final int headerLength;

    if (usesPassphrase) {
      final pass = passphrase ?? '';
      if (pass.isEmpty) {
        throw const LinkCryptoException('النص ده محتاج كلمة سر');
      }
      headerLength = _headerLength + _saltLength;
      if (data.length < headerLength + _nonceLength + _macLength) {
        throw const LinkCryptoException('النص المشفّر ناقص أو متعدّل');
      }
      final salt = Uint8List.sublistView(data, _headerLength, headerLength);
      key = await _passphraseKey(pass, salt, deviceOnly: deviceOnly);
      cipher = _cipher256;
    } else if (deviceOnly) {
      headerLength = _headerLength;
      key = await _loadDeviceKey();
      cipher = _cipher256;
    } else {
      headerLength = _headerLength + _embeddedKeyLength;
      if (data.length < headerLength + _nonceLength + _macLength) {
        throw const LinkCryptoException('النص المشفّر ناقص أو متعدّل');
      }
      key = Uint8List.sublistView(data, _headerLength, headerLength);
      cipher = _cipher128;
    }

    final header = Uint8List.sublistView(data, 0, headerLength);
    final body = Uint8List.sublistView(data, headerLength);

    Uint8List clearBytes;
    try {
      final box = SecretBox.fromConcatenation(
        body,
        nonceLength: _nonceLength,
        macLength: _macLength,
      );
      final clear = await cipher.decrypt(box, secretKey: SecretKey(key), aad: header);
      clearBytes = Uint8List.fromList(clear);
    } catch (_) {
      throw LinkCryptoException(
        usesPassphrase
            ? (deviceOnly
                ? 'كلمة السر غلط، أو النص ده اتشفّر على جهاز تاني'
                : 'كلمة السر غلط، أو النص اتعدّل')
            : deviceOnly
                ? 'النص ده اتشفّر على جهاز تاني، أو مفتاح الجهاز اتغيّر أو اتمسح'
                : 'النص المشفّر اتعدّل أو ناقص',
      );
    }

    try {
      final decodedBytes = clearBytes;
      if (!compressed) return _validateDecryptedUrl(utf8.decode(decodedBytes));
      final output = _BoundedByteSink();
      final decoder = ZLibDecoder().startChunkedConversion(output);
      decoder.add(decodedBytes);
      decoder.close();
      return _validateDecryptedUrl(utf8.decode(output.takeBytes()));
    } on LinkCryptoException {
      rethrow;
    } on FormatException {
      throw const LinkCryptoException('النص المشفّر ناقص أو متعدّل أو حجمه غير مسموح');
    } catch (_) {
      throw const LinkCryptoException('النص المشفّر ناقص أو متعدّل');
    }
  }

  String _validateDecryptedUrl(String value) {
    if (value.isEmpty ||
        value != value.trim() ||
        _containsUnsafeUnicode(value) ||
        _containsControlCharacters(value)) {
      throw const LinkCryptoException('الرابط المفكوك غير صالح أو يحتوي على حروف مخفية');
    }
    if (utf8.encode(value).length > _maxUrlBytes) {
      throw const LinkCryptoException('الرابط المفكوك أطول من الحد المسموح');
    }
    final parsed = Uri.tryParse(value);
    if (parsed == null ||
        (parsed.scheme != 'https' && parsed.scheme != 'http') ||
        parsed.host.isEmpty ||
        parsed.userInfo.isNotEmpty) {
      throw const LinkCryptoException('الرابط المفكوك ليس عنوان HTTP أو HTTPS صالحًا');
    }
    return value;
  }

  /// Argon2id(passphrase, salt) is deliberately slow. With [deviceOnly] the
  /// result is mixed with the device key (HKDF), so both are needed.
  Future<List<int>> _passphraseKey(
    String pass,
    List<int> salt, {
    required bool deviceOnly,
  }) async {
    final stretched = await _kdf.deriveKeyFromPassword(
      password: pass,
      nonce: salt,
    );
    final stretchedBytes = await stretched.extractBytes();
    if (!deviceOnly) return stretchedBytes;

    final deviceKey = await _loadDeviceKey();
    final mixed = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey([...stretchedBytes, ...deviceKey]),
      nonce: salt,
      info: utf8.encode('linklock-v3-passphrase+device'),
    );
    return mixed.extractBytes();
  }

  Future<List<int>> _loadDeviceKey() async {
    try {
      final key = await _deviceKeyProvider();
      if (key.length != _deviceKeyLength) {
        throw const FormatException('unexpected key length');
      }
      return key;
    } catch (_) {
      throw const LinkCryptoException('مقدرتش أوصل لمفتاح الجهاز');
    }
  }

  /// Deflate-compresses [data] and returns it only if that's actually
  /// smaller; otherwise returns the original bytes unchanged. Compression is
  /// a size optimization, never a requirement, so any failure just falls
  /// back to the raw bytes.
  (Uint8List, bool) _maybeCompress(Uint8List data) {
    try {
      final compressed = Uint8List.fromList(ZLibCodec(level: 9).encode(data));
      if (compressed.length < data.length) {
        return (compressed, true);
      }
    } catch (_) {
      // Fall through to the uncompressed bytes below.
    }
    return (data, false);
  }

  Uint8List _randomBytes(int length) => Uint8List.fromList(
        List<int>.generate(length, (_) => _random.nextInt(256)),
      );
}
