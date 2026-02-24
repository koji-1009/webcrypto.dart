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

Future<RsaSsaPkcs1V15PrivateKeyImpl> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaSsaPkcs1v15PrivateKeyImpl(
    ssl.RsaKey.importPkcs8(Uint8List.fromList(keyData)),
    hash,
  );
}

Future<RsaSsaPkcs1V15PrivateKeyImpl> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  final k = JsonWebKey.fromJson(jwk);
  final h = _HashImpl.fromHash(hash);

  _checkJwkRsa(
    k,
    isPrivateKey: true,
    expectedAlg: h.rsassaPkcs1V15JwkAlg,
    expectedUse: 'sig',
  );
  return _RsaSsaPkcs1v15PrivateKeyImpl(
    _importJwkRsa(k, isPrivateKey: true),
    hash,
  );
}

Future<KeyPair<RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl>>
rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  return _generateRsaKeyPair(
    modulusLength,
    publicExponent,
    (k) => _RsaSsaPkcs1v15PrivateKeyImpl(k, hash),
    (k) => _RsaSsaPkcs1v15PublicKeyImpl(k, hash),
  );
}

Future<RsaSsaPkcs1V15PublicKeyImpl> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaSsaPkcs1v15PublicKeyImpl(
    ssl.RsaKey.importSpki(Uint8List.fromList(keyData)),
    hash,
  );
}

Future<RsaSsaPkcs1V15PublicKeyImpl> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  final k = JsonWebKey.fromJson(jwk);
  final h = _HashImpl.fromHash(hash);

  _checkJwkRsa(
    k,
    isPrivateKey: false,
    expectedAlg: h.rsassaPkcs1V15JwkAlg,
    expectedUse: 'sig',
  );
  return _RsaSsaPkcs1v15PublicKeyImpl(
    _importJwkRsa(k, isPrivateKey: false),
    hash,
  );
}

final class _StaticRsaSsaPkcs1PrivateKeyImpl
    implements StaticRsaSsaPkcs1v15PrivateKeyImpl {
  const _StaticRsaSsaPkcs1PrivateKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) => rsassaPkcs1V15PrivateKey_importPkcs8Key(keyData, hash);

  @override
  Future<RsaSsaPkcs1V15PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) => rsassaPkcs1V15PrivateKey_importJsonWebKey(jwk, hash);

  @override
  Future<(RsaSsaPkcs1V15PrivateKeyImpl, RsaSsaPkcs1V15PublicKeyImpl)>
  generateKey(int modulusLength, BigInt publicExponent, HashImpl hash) async {
    final keyPair = await rsassaPkcs1V15PrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _RsaSsaPkcs1v15PrivateKeyImpl
    implements RsaSsaPkcs1V15PrivateKeyImpl {
  final ssl.RsaKey _key;
  final HashImpl _hash;

  _RsaSsaPkcs1v15PrivateKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaSsaPkcs1v15PrivateKey\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    try {
      return ssl.RsaSsaPkcs1.sign(
        _key,
        Uint8List.fromList(data),
        _HashImpl.fromHash(_hash).hashName,
      );
    } catch (e) {
      throw operationError('RSASSA-PKCS1-v1_5 sign failed: $e');
    }
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    try {
      final buffer = BytesBuilder();
      await for (final chunk in data) {
        buffer.add(chunk);
      }
      return ssl.RsaSsaPkcs1.sign(
        _key,
        buffer.toBytes(),
        _HashImpl.fromHash(_hash).hashName,
      );
    } catch (e) {
      throw operationError('RSASSA-PKCS1-v1_5 sign stream failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final h = _HashImpl.fromHash(_hash);
    return _exportJwkRsa(
      _key,
      isPrivateKey: true,
      jwkAlg: h.rsassaPkcs1V15JwkAlg,
      jwkUse: 'sig',
    );
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _key.exportPkcs8();
}

final class _StaticRsaSsaPkcs1PublicKeyImpl
    implements StaticRsaSsaPkcs1v15PublicKeyImpl {
  const _StaticRsaSsaPkcs1PublicKeyImpl();

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) => rsassaPkcs1V15PublicKey_importSpkiKey(keyData, hash);

  @override
  Future<RsaSsaPkcs1V15PublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) => rsassaPkcs1V15PublicKey_importJsonWebKey(jwk, hash);
}

final class _RsaSsaPkcs1v15PublicKeyImpl
    implements RsaSsaPkcs1V15PublicKeyImpl {
  final ssl.RsaKey _key;
  final HashImpl _hash;

  _RsaSsaPkcs1v15PublicKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaSsaPkcs1v15PublicKey\'';
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    try {
      return ssl.RsaSsaPkcs1.verify(
        _key,
        Uint8List.fromList(signature),
        Uint8List.fromList(data),
        _HashImpl.fromHash(_hash).hashName,
      );
    } catch (e) {
      return false;
    }
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    try {
      final buffer = BytesBuilder();
      await for (final chunk in data) {
        buffer.add(chunk);
      }
      return verifyBytes(signature, buffer.toBytes());
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
      jwkAlg: h.rsassaPkcs1V15JwkAlg,
      jwkUse: 'sig',
    );
  }

  @override
  Future<Uint8List> exportSpkiKey() async => _key.exportSpki();
}
