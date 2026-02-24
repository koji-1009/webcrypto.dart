// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

part of 'impl_ffi.dart';

Future<KeyPair<S, T>> _generateRsaKeyPair<S, T>(
  int modulusLength,
  BigInt publicExponent,
  // Helper factories to create the specific implementation instances
  S Function(ssl.RsaKey) privateKeyFactory,
  T Function(ssl.RsaKey) publicKeyFactory,
) async {
  if (modulusLength < 256 || modulusLength > 16384) {
    throw UnsupportedError(
      'modulusLength must between 256 and 16k, $modulusLength is not supported',
    );
  }
  if ((modulusLength % 8) != 0) {
    throw UnsupportedError(
      'modulusLength: $modulusLength is not a multiple of 8',
    );
  }
  if (publicExponent != BigInt.from(3) &&
      publicExponent != BigInt.from(65537)) {
    throw UnsupportedError('publicExponent is not supported, try 3 or 65537');
  }

  // Generate in Isolate to avoid blocking
  final pkcs8 = await Isolate.run(() {
    // We pass modulusLength and publicExponent (BigInt is sendable)
    final key = ssl.RsaKey.generate(modulusLength, publicExponent);
    return key.exportPkcs8();
  }, debugName: 'RSA_generate');

  // Import on main isolate
  final privateKey = ssl.RsaKey.importPkcs8(pkcs8);

  // Derive public key (via SPKI export/import to separate objects)
  final spki = privateKey.exportSpki();
  final publicKey = ssl.RsaKey.importSpki(spki);

  return (
    privateKey: privateKeyFactory(privateKey),
    publicKey: publicKeyFactory(publicKey),
  );
}

// Helpers for JWK
void _checkJwkRsa(
  JsonWebKey jwk, {
  required bool isPrivateKey,
  required String expectedAlg,
  required String expectedUse,
}) {
  if (jwk.kty != 'RSA') {
    throw const FormatException('JWK "kty" must be "RSA"');
  }
  if (jwk.alg != null && jwk.alg != expectedAlg) {
    throw FormatException('JWK "alg" must be "$expectedAlg"');
  }
  if (jwk.use != null && jwk.use != expectedUse) {
    throw FormatException('JWK "use" must be "$expectedUse"');
  }
  if (jwk.n == null || jwk.e == null) {
    throw const FormatException('JWK "n" and "e" must be present');
  }
  if (isPrivateKey) {
    if (jwk.d == null) {
      throw const FormatException('JWK "d" must be present for private keys');
    }
    if (jwk.p == null ||
        jwk.q == null ||
        jwk.dp == null ||
        jwk.dq == null ||
        jwk.qi == null) {
      throw const FormatException(
        'JWK "p", "q", "dp", "dq", "qi" must be present for private keys',
      );
    }
  } else {
    if (jwk.d != null) {
      throw const FormatException(
        'JWK "d" must not be present for public keys',
      );
    }
  }
}

ssl.RsaKey _importJwkRsa(JsonWebKey jwk, {required bool isPrivateKey}) {
  Uint8List d(String? s) =>
      s != null ? _jwkDecodeBase64UrlNoPadding(s, '') : Uint8List(0);

  return ssl.RsaKey.importComponents(
    n: d(jwk.n),
    e: d(jwk.e),
    d: isPrivateKey ? d(jwk.d) : null,
    p: isPrivateKey ? d(jwk.p) : null,
    q: isPrivateKey ? d(jwk.q) : null,
    dp: isPrivateKey ? d(jwk.dp) : null,
    dq: isPrivateKey ? d(jwk.dq) : null,
    qi: isPrivateKey ? d(jwk.qi) : null,
  );
}

Map<String, dynamic> _exportJwkRsa(
  ssl.RsaKey key, {
  required bool isPrivateKey,
  required String jwkAlg,
  required String jwkUse,
}) {
  final c = key.exportComponents(includePrivate: isPrivateKey);
  String e(String k) => c[k] != null ? _jwkEncodeBase64UrlNoPadding(c[k]!) : '';

  return JsonWebKey(
    kty: 'RSA',
    use: jwkUse,
    alg: jwkAlg,
    n: e('n'),
    e: e('e'),
    d: isPrivateKey ? e('d') : null,
    p: isPrivateKey ? e('p') : null,
    q: isPrivateKey ? e('q') : null,
    dp: isPrivateKey ? e('dp') : null,
    dq: isPrivateKey ? e('dq') : null,
    qi: isPrivateKey ? e('qi') : null,
  ).toJson();
}
