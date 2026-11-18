import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:linklock/recovery_code.dart';

void main() {
  final random = Random(7);
  List<int> newKey() => List<int>.generate(32, (_) => random.nextInt(256));

  test('round trip restores the exact key', () {
    for (var i = 0; i < 50; i++) {
      final key = newKey();
      expect(RecoveryCode.decode(RecoveryCode.encode(key)), key);
    }
  });

  test('is 55 characters in groups of 5 and tolerant of case and spaces', () {
    final key = newKey();
    final code = RecoveryCode.encode(key);
    expect(code.replaceAll('-', '').length, 55);
    expect(RecoveryCode.decode(code.toLowerCase().replaceAll('-', ' ')), key);
  });

  test('a single wrong character is rejected', () {
    final code = RecoveryCode.encode(newKey());
    final flipped = (code[0] == 'A' ? 'B' : 'A') + code.substring(1);
    expect(RecoveryCode.decode(flipped), isNull);
  });

  test('garbage and wrong lengths are rejected', () {
    expect(RecoveryCode.decode(''), isNull);
    expect(RecoveryCode.decode('hello world'), isNull);
    expect(RecoveryCode.decode('AAAAA-AAAAA'), isNull);
  });
}
