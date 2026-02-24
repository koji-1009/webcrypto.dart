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

Future<RsaPssPrivateKeyImpl> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaPssPrivateKeyImpl(
    ssl.RsaKey.importPkcs8(Uint8List.fromList(keyData)),
    hash,
  );
}

Future<RsaPssPrivateKeyImpl> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  final k = JsonWebKey.fromJson(jwk);
  final h = _HashImpl.fromHash(hash);

  _checkJwkRsa(
    k,
    isPrivateKey: true,
    expectedAlg: h.rsaPssJwkAlg,
    expectedUse: 'sig',
  );
  return _RsaPssPrivateKeyImpl(_importJwkRsa(k, isPrivateKey: true), hash);
}

Future<KeyPair<RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl>>
rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  return _generateRsaKeyPair(
    modulusLength,
    publicExponent,
    (k) => _RsaPssPrivateKeyImpl(k, hash),
    (k) => _RsaPssPublicKeyImpl(k, hash),
  );
}

Future<RsaPssPublicKeyImpl> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaPssPublicKeyImpl(
    ssl.RsaKey.importSpki(Uint8List.fromList(keyData)),
    hash,
  );
}

Future<RsaPssPublicKeyImpl> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  final k = JsonWebKey.fromJson(jwk);
  final h = _HashImpl.fromHash(hash);

  _checkJwkRsa(
    k,
    isPrivateKey: false,
    expectedAlg: h.rsaPssJwkAlg,
    expectedUse: 'sig',
  );
  return _RsaPssPublicKeyImpl(_importJwkRsa(k, isPrivateKey: false), hash);
}

final class _StaticRsaPssPrivateKeyImpl implements StaticRsaPssPrivateKeyImpl {
  const _StaticRsaPssPrivateKeyImpl();

  @override
  Future<RsaPssPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) => rsaPssPrivateKey_importPkcs8Key(keyData, hash);

  @override
  Future<RsaPssPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) => rsaPssPrivateKey_importJsonWebKey(jwk, hash);

  @override
  Future<(RsaPssPrivateKeyImpl, RsaPssPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final keyPair = await rsaPssPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _RsaPssPrivateKeyImpl implements RsaPssPrivateKeyImpl {
  final ssl.RsaKey _key;
  final HashImpl _hash;

  _RsaPssPrivateKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaPssPrivateKey\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) async {
    try {
      return ssl.RsaPss.sign(
        _key,
        Uint8List.fromList(data),
        saltLength,
        _HashImpl.fromHash(_hash).hashName,
      );
    } catch (e) {
      throw operationError('RSA-PSS sign failed: $e');
    }
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) async {
    try {
      final buffer = BytesBuilder();
      await for (final chunk in data) {
        buffer.add(chunk);
      }
      return ssl.RsaPss.sign(
        _key,
        buffer.toBytes(),
        saltLength,
        _HashImpl.fromHash(_hash).hashName,
      );
    } catch (e) {
      throw operationError('RSA-PSS sign stream failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final h = _HashImpl.fromHash(_hash);
    return _exportJwkRsa(
      _key,
      isPrivateKey: true,
      jwkAlg: h.rsaPssJwkAlg,
      jwkUse: 'sig',
    );
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _key.exportPkcs8();
}

final class _StaticRsaPssPublicKeyImpl implements StaticRsaPssPublicKeyImpl {
  const _StaticRsaPssPublicKeyImpl();

  @override
  Future<RsaPssPublicKeyImpl> importSpkiKey(List<int> keyData, HashImpl hash) =>
      rsaPssPublicKey_importSpkiKey(keyData, hash);

  @override
  Future<RsaPssPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) => rsaPssPublicKey_importJsonWebKey(jwk, hash);
}

final class _RsaPssPublicKeyImpl implements RsaPssPublicKeyImpl {
  final ssl.RsaKey _key;
  final HashImpl _hash;

  _RsaPssPublicKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaPssPublicKey\'';
  }

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) async {
    try {
      return ssl.RsaPss.verify(
        _key,
        Uint8List.fromList(signature),
        Uint8List.fromList(data),
        saltLength,
        _HashImpl.fromHash(_hash).hashName,
      );
    } catch (e) {
      return false;
    }
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) async {
    try {
      final buffer = BytesBuilder();
      await for (final chunk in data) {
        buffer.add(chunk);
      }
      return verifyBytes(signature, buffer.toBytes(), saltLength);
    } catch (e) {
      return false;
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final h = _HashImpl.fromHash(_hash);
    return _exportJwkRsa(
      _key,
      isPrivateKey: false,
      jwkAlg: h.rsaPssJwkAlg,
      jwkUse: 'sig',
    );
  }

  @override
  Future<Uint8List> exportSpkiKey() async => _key.exportSpki();
}
