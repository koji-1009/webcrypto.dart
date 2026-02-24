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

// ignore_for_file: non_constant_identifier_names

part of 'impl_ffi.dart';

String _ecdsaCurveToJwkAlg(EllipticCurve curve) {
  return switch (curve) {
    EllipticCurve.p256 => 'ES256',
    EllipticCurve.p384 => 'ES384',
    EllipticCurve.p521 => 'ES512',
  };
}

Future<EcdsaPrivateKeyImpl> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKeyImpl(
    ssl.EcKey.importPkcs8(Uint8List.fromList(keyData), _ecCurveName(curve)),
  );
}

Future<EcdsaPrivateKeyImpl> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  final k = JsonWebKey.fromJson(jwk);
  _checkJwkEc(
    k,
    isPrivateKey: true,
    expectedUse: 'sig',
    curveName: _ecCurveName(curve),
    expectedAlg: _ecdsaCurveToJwkAlg(curve),
  );
  return _EcdsaPrivateKeyImpl(_importJwkEc(k, curve, isPrivateKey: true));
}

Future<KeyPair<EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl>>
ecdsaPrivateKey_generateKey(EllipticCurve curve) async {
  final key = ssl.EcKey.generate(_ecCurveName(curve));
  // EcKey contains both private (and public) parts.
  // We need to support separating them if needed, but boringssl_dart EcKey holds both if generated.
  // EcdsaPrivateKeyImpl holds the full key.
  // EcdsaPublicKeyImpl should hold a key that only has public part?
  // But here we generate a full key.
  // We can share the same underlying key object, or clone it?
  // BoringSSL PKEY references can be shared if refcounted, but `boringssl_dart` wrapper owns it.
  // `generate` returns one `EcKey`.
  // I cannot wrap the *same* `EcKey` instance in two different Impls if they both try to free it (via finalizer/dispose).
  // If I share the instance: `priv = Impl(k)`, `pub = Impl(k)`.
  // If `priv` is explicitly closed, `k` is invalid.
  // If `pub` is used, it crashes.
  // However, WebCrypto `KeyPair` has distinct `publicKey` and `privateKey` objects.
  // Re-importing coordinates is safe standard way.

  final coords = key.exportCoordinates();
  final pubKey = ssl.EcKey.importCoordinates(
    curve: key.curve,
    x: coords['x']!,
    y: coords['y']!,
  );

  return (
    privateKey: _EcdsaPrivateKeyImpl(key),
    publicKey: _EcdsaPublicKeyImpl(pubKey),
  );
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  // Raw import logic usually involves Octet-to-Point.
  // boringssl_dart `EcKey.importCoordinates` expects x/y.
  // I need to parse raw key (0x04 | x | y).
  // `impl_boringssl` `ec_common.dart` used `EC_POINT_oct2point`.
  // `boringssl_dart` doesn't expose `oct2point`.
  // I should manually parse the raw key if it's standard 0x04 uncompressed format.
  // If `keyData[0] == 0x04`.
  // Len = 1 + 2*coordLen.
  final k = Uint8List.fromList(keyData);
  if (k.isEmpty || k[0] != 0x04) {
    throw ArgumentError(
      'Invalid raw EC key format (must be uncompressed 0x04)',
    );
  }
  // coordLen = (k.length - 1) / 2
  if ((k.length - 1) % 2 != 0) {
    throw ArgumentError('Invalid raw EC key length');
  }
  final coordLen = (k.length - 1) ~/ 2;
  final x = k.sublist(1, 1 + coordLen);
  final y = k.sublist(1 + coordLen);

  return _EcdsaPublicKeyImpl(
    ssl.EcKey.importCoordinates(curve: _ecCurveName(curve), x: x, y: y),
  );
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKeyImpl(
    ssl.EcKey.importSpki(Uint8List.fromList(keyData), _ecCurveName(curve)),
  );
}

Future<EcdsaPublicKeyImpl> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  final k = JsonWebKey.fromJson(jwk);
  _checkJwkEc(
    k,
    isPrivateKey: false,
    expectedUse: 'sig',
    curveName: _ecCurveName(curve),
    expectedAlg: _ecdsaCurveToJwkAlg(curve),
  );
  return _EcdsaPublicKeyImpl(_importJwkEc(k, curve, isPrivateKey: false));
}

final class _StaticEcdsaPrivateKeyImpl implements StaticEcdsaPrivateKeyImpl {
  const _StaticEcdsaPrivateKeyImpl();

  @override
  Future<EcdsaPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) => ecdsaPrivateKey_importPkcs8Key(keyData, curve);

  @override
  Future<EcdsaPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) => ecdsaPrivateKey_importJsonWebKey(jwk, curve);

  @override
  Future<(EcdsaPrivateKeyImpl, EcdsaPublicKeyImpl)> generateKey(
    EllipticCurve curve,
  ) async {
    final keyPair = await ecdsaPrivateKey_generateKey(curve);
    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _EcdsaPrivateKeyImpl implements EcdsaPrivateKeyImpl {
  final ssl.EcKey _key;
  _EcdsaPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdsaPrivateKeyImpl\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data, HashImpl hash) async {
    return ssl.Ecdsa.sign(
      _key,
      Uint8List.fromList(data),
      _HashImpl.fromHash(hash).hashName,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, HashImpl hash) async {
    // boringssl_dart Ecdsa.sign is one-shot.
    // We can buffer the stream or use EVP_DigestSign* logic?
    // webcrypto requires buffering for signing if no streaming interface?
    // Actually hashing is streaming, but signing acts on hash?
    // Ecdsa.sign takes DATA. It hashes it? Yes, it takes hashAlgorithm.
    // To support streaming input to sign, we need streaming hash then sign?
    // But `Ecdsa.sign` does hash+sign.
    // Does `boringssl_dart` support streaming sign?
    // Step 1579: `Ecdsa` class only has static `sign`, `verify`. No context.
    // So we must buffer.

    final buffer = BytesBuilder();
    await for (final chunk in data) {
      buffer.add(chunk);
    }
    return ssl.Ecdsa.sign(
      _key,
      buffer.toBytes(),
      _HashImpl.fromHash(hash).hashName,
    );
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEc(_key, isPrivateKey: true, jwkUse: 'sig');

  @override
  Future<Uint8List> exportPkcs8Key() async => _key.exportPkcs8();
}

final class _StaticEcdsaPublicKeyImpl implements StaticEcdsaPublicKeyImpl {
  const _StaticEcdsaPublicKeyImpl();

  @override
  Future<EcdsaPublicKeyImpl> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) => ecdsaPublicKey_importRawKey(keyData, curve);

  @override
  Future<EcdsaPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) => ecdsaPublicKey_importJsonWebKey(jwk, curve);

  @override
  Future<EcdsaPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) => ecdsaPublicKey_importSpkiKey(keyData, curve);
}

final class _EcdsaPublicKeyImpl implements EcdsaPublicKeyImpl {
  final ssl.EcKey _key;
  _EcdsaPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdsaPublicKeyImpl\'';
  }

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    HashImpl hash,
  ) async {
    try {
      final result = ssl.Ecdsa.verify(
        _key,
        Uint8List.fromList(signature),
        Uint8List.fromList(data),
        _HashImpl.fromHash(hash).hashName,
      );
      if (!result) {}
      return result;
    } catch (e) {
      return false;
    }
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    HashImpl hash,
  ) async {
    try {
      final buffer = BytesBuilder();
      await for (final chunk in data) {
        buffer.add(chunk);
      }
      return ssl.Ecdsa.verify(
        _key,
        Uint8List.fromList(signature),
        buffer.toBytes(),
        _HashImpl.fromHash(hash).hashName,
      );
    } catch (e) {
      return false;
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEc(_key, isPrivateKey: false, jwkUse: 'sig');

  @override
  Future<Uint8List> exportRawKey() async {
    // Export RAW key (0x04 | x | y)
    final coords = _key.exportCoordinates();
    final x = coords['x']!;
    final y = coords['y']!;

    final out = Uint8List(1 + x.length + y.length);
    out[0] = 0x04;
    out.setAll(1, x);
    out.setAll(1 + x.length, y);
    return out;
  }

  @override
  Future<Uint8List> exportSpkiKey() async => _key.exportSpki();
}
