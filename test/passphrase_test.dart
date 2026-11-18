import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:linklock/crypto_service.dart';

void main() {
  // Cheap Argon2id so tests stay fast; production uses LinkCrypto.defaultKdf.
  final kdf = Argon2id(parallelism: 1, memory: 64, iterations: 1, hashLength: 32);
  final deviceA = List<int>.generate(32, (i) => i);
  final deviceB = List<int>.generate(32, (i) => 255 - i);

  LinkCrypto cryptoFor(List<int> key) =>
      LinkCrypto(deviceKeyProvider: () async => key, kdf: kdf);

  const link = 'https://example.com/secret?a=1';
  const pass = 'correct horse battery staple';

  test('passphrase-only opens on any device, only with the passphrase', () async {
    final token = await cryptoFor(deviceA).encrypt(link, passphrase: pass);

    expect(await cryptoFor(deviceB).decrypt(token, passphrase: pass), link);
    expect(
      () => cryptoFor(deviceA).decrypt(token, passphrase: 'wrong passphrase'),
      throwsA(isA<LinkCryptoException>()),
    );
    expect(
      () => cryptoFor(deviceA).decrypt(token),
      throwsA(isA<LinkCryptoException>()),
    );
  });

  test('passphrase + device needs both', () async {
    final token = await cryptoFor(deviceA)
        .encrypt(link, deviceOnly: true, passphrase: pass);

    expect(await cryptoFor(deviceA).decrypt(token, passphrase: pass), link);
    expect(
      () => cryptoFor(deviceB).decrypt(token, passphrase: pass),
      throwsA(isA<LinkCryptoException>()),
    );
    expect(
      () => cryptoFor(deviceA).decrypt(token, passphrase: 'nope nope nope'),
      throwsA(isA<LinkCryptoException>()),
    );
  });

  test('a modified passphrase token is rejected', () async {
    final token = await cryptoFor(deviceA).encrypt(link, passphrase: pass);
    final i = token.length - 3;
    final forged =
        token.substring(0, i) + (token[i] == 'A' ? 'B' : 'A') + token.substring(i + 1);
    expect(
      () => cryptoFor(deviceA).decrypt(forged, passphrase: pass),
      throwsA(isA<LinkCryptoException>()),
    );
  });

  test('same link and passphrase give different tokens (fresh salt)', () async {
    final c = cryptoFor(deviceA);
    final a = await c.encrypt(link, passphrase: pass);
    final b = await c.encrypt(link, passphrase: pass);
    expect(a, isNot(b));
  });
}
