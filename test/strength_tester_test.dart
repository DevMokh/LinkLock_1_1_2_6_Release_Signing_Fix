import 'package:flutter_test/flutter_test.dart';
import 'package:linklock/strength_tester.dart';

void main() {
  const link = 'https://example.com/path?a=1&b=two#frag';
  final tester = StrengthTester();

  test('shareable mode: key travels with the token (camouflage only)', () async {
    final r = await tester.run(link, deviceOnly: false, samples: 50, tamperRuns: 50);

    expect(r.keyInsideToken, isTrue);
    expect(r.openedByStranger, isTrue);
    expect(r.strong, isFalse);
    // Still well-formed: nothing repeats and every edit is detected.
    expect(r.noRepeats, isTrue);
    expect(r.tamperProof, isTrue);
    expect(r.entropy, greaterThan(7.0));
  });

  test('rejects invalid sample counts', () async {
    await expectLater(
      tester.run(link, deviceOnly: false, samples: 0),
      throwsA(isA<RangeError>()),
    );
  });

  test('device-only mode: stranger with the token cannot open it', () async {
    final r = await tester.run(link, deviceOnly: true, samples: 50, tamperRuns: 50);

    expect(r.keyInsideToken, isFalse);
    expect(r.openedByStranger, isFalse);
    expect(r.noRepeats, isTrue);
    expect(r.tamperProof, isTrue);
    expect(r.strong, isTrue);
    expect(r.entropy, greaterThan(7.0));
  });
}
