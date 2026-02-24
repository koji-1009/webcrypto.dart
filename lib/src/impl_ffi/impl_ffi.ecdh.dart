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

Future<EcdhPrivateKeyImpl> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPrivateKeyImpl(
    ssl.EcKey.importPkcs8(Uint8List.fromList(keyData), _ecCurveName(curve)),
  );
}

Future<EcdhPrivateKeyImpl> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  final k = JsonWebKey.fromJson(jwk);
  _checkJwkEc(
    k,
    isPrivateKey: true,
    expectedUse: 'enc',
    curveName: _ecCurveName(curve),
    expectedAlg: null,
  );
  return _EcdhPrivateKeyImpl(_importJwkEc(k, curve, isPrivateKey: true));
}

Future<KeyPair<EcdhPrivateKeyImpl, EcdhPublicKeyImpl>>
ecdhPrivateKey_generateKey(EllipticCurve curve) async {
  final key = ssl.EcKey.generate(_ecCurveName(curve));

  // Clone public key logic (same as ECDSA)
  final coords = key.exportCoordinates();
  final pubKey = ssl.EcKey.importCoordinates(
    curve: key.curve,
    x: coords['x']!,
    y: coords['y']!,
  );

  return (
    privateKey: _EcdhPrivateKeyImpl(key),
    publicKey: _EcdhPublicKeyImpl(pubKey),
  );
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  // Manual raw parsing
  final k = Uint8List.fromList(keyData);
  if (k.isEmpty || k[0] != 0x04) {
    throw ArgumentError('Invalid raw EC key format (must be 0x04)');
  }
  if ((k.length - 1) % 2 != 0) {
    throw ArgumentError('Invalid raw EC key length');
  }
  final coordLen = (k.length - 1) ~/ 2;
  final x = k.sublist(1, 1 + coordLen);
  final y = k.sublist(1 + coordLen);

  return _EcdhPublicKeyImpl(
    ssl.EcKey.importCoordinates(curve: _ecCurveName(curve), x: x, y: y),
  );
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdhPublicKeyImpl(
    ssl.EcKey.importSpki(Uint8List.fromList(keyData), _ecCurveName(curve)),
  );
}

Future<EcdhPublicKeyImpl> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  final k = JsonWebKey.fromJson(jwk);
  _checkJwkEc(
    k,
    isPrivateKey: false,
    expectedUse: 'enc',
    curveName: _ecCurveName(curve),
    expectedAlg: null,
  );
  return _EcdhPublicKeyImpl(_importJwkEc(k, curve, isPrivateKey: false));
}

final class _StaticEcdhPrivateKeyImpl implements StaticEcdhPrivateKeyImpl {
  const _StaticEcdhPrivateKeyImpl();

  @override
  Future<EcdhPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) => ecdhPrivateKey_importPkcs8Key(keyData, curve);

  @override
  Future<EcdhPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) => ecdhPrivateKey_importJsonWebKey(jwk, curve);

  @override
  Future<(EcdhPrivateKeyImpl, EcdhPublicKeyImpl)> generateKey(
    EllipticCurve curve,
  ) async {
    final keyPair = await ecdhPrivateKey_generateKey(curve);
    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _EcdhPrivateKeyImpl implements EcdhPrivateKeyImpl {
  final ssl.EcKey _key;
  _EcdhPrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdhPrivateKey\'';
  }

  @override
  Future<Uint8List> deriveBits(int length, EcdhPublicKeyImpl publicKey) async {
    if (publicKey is! _EcdhPublicKeyImpl) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'unsupported key implementation',
      );
    }
    final pubKey = publicKey._key;

    // Check curves match?
    if (pubKey.curve != _key.curve) {
      throw ArgumentError('Curves mismatch');
    }

    try {
      return ssl.Ecdh.computeBits(_key, pubKey, length);
    } catch (e) {
      throw operationError('ECDH deriveBits failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEc(_key, isPrivateKey: true, jwkUse: 'enc');

  @override
  Future<Uint8List> exportPkcs8Key() async => _key.exportPkcs8();
}

final class _StaticEcdhPublicKeyImpl implements StaticEcdhPublicKeyImpl {
  const _StaticEcdhPublicKeyImpl();

  @override
  Future<EcdhPublicKeyImpl> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) => ecdhPublicKey_importRawKey(keyData, curve);

  @override
  Future<EcdhPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) => ecdhPublicKey_importSpkiKey(keyData, curve);

  @override
  Future<EcdhPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) => ecdhPublicKey_importJsonWebKey(jwk, curve);
}

final class _EcdhPublicKeyImpl implements EcdhPublicKeyImpl {
  final ssl.EcKey _key;
  _EcdhPublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'EcdhPublicKey\'';
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkEc(_key, isPrivateKey: false, jwkUse: 'enc');

  @override
  Future<Uint8List> exportRawKey() async {
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
