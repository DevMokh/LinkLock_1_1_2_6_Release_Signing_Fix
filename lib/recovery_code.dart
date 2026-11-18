import 'dart:math';

/// Turns the 32-byte device key into a short code you can write on paper
/// (like a wallet's backup phrase) and turns it back into the key.
///
/// Code = Base32( key(32 bytes) + CRC-16 ) in groups of 5: 55 characters.
/// The CRC only catches typos; it adds no secrecy. Whoever holds the code
/// holds the key.
class RecoveryCode {
  static const int keyLength = 32;
  static const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  static String encode(List<int> key) {
    if (key.length != keyLength) {
      throw ArgumentError('key must be $keyLength bytes');
    }
    final crc = _crc16(key);
    final text = _base32Encode([...key, crc >> 8, crc & 0xFF]);
    final groups = <String>[];
    for (var i = 0; i < text.length; i += 5) {
      groups.add(text.substring(i, min(i + 5, text.length)));
    }
    return groups.join('-');
  }

  /// Returns the key, or null if the code is malformed or has a typo.
  static List<int>? decode(String input) {
    final clean = input.toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
    final bytes = _base32Decode(clean);
    if (bytes == null || bytes.length != keyLength + 2) return null;
    final key = bytes.sublist(0, keyLength);
    final crc = (bytes[keyLength] << 8) | bytes[keyLength + 1];
    return crc == _crc16(key) ? key : null;
  }

  static String _base32Encode(List<int> data) {
    final out = StringBuffer();
    var buffer = 0;
    var bits = 0;
    for (final b in data) {
      buffer = (buffer << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out.write(_alphabet[(buffer >> (bits - 5)) & 31]);
        bits -= 5;
      }
      buffer &= (1 << bits) - 1;
    }
    if (bits > 0) out.write(_alphabet[(buffer << (5 - bits)) & 31]);
    return out.toString();
  }

  static List<int>? _base32Decode(String text) {
    final out = <int>[];
    var buffer = 0;
    var bits = 0;
    for (var i = 0; i < text.length; i++) {
      final v = _alphabet.indexOf(text[i]);
      if (v < 0) return null;
      buffer = (buffer << 5) | v;
      bits += 5;
      if (bits >= 8) {
        out.add((buffer >> (bits - 8)) & 0xFF);
        bits -= 8;
        buffer &= (1 << bits) - 1;
      }
    }
    return out;
  }

  static int _crc16(List<int> data) {
    var crc = 0xFFFF;
    for (final b in data) {
      crc ^= b << 8;
      for (var i = 0; i < 8; i++) {
        crc = (crc & 0x8000) != 0
            ? ((crc << 1) ^ 0x1021) & 0xFFFF
            : (crc << 1) & 0xFFFF;
      }
    }
    return crc;
  }
}
