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

Future<RsaOaepPrivateKeyImpl> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaOaepPrivateKeyImpl(
    ssl.RsaKey.importPkcs8(Uint8List.fromList(keyData)),
    hash,
  );
}

Future<RsaOaepPrivateKeyImpl> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  final k = JsonWebKey.fromJson(jwk);
  final h = _HashImpl.fromHash(hash);

  _checkJwkRsa(
    k,
    isPrivateKey: true,
    expectedAlg: h.rsaOaepJwkAlg,
    expectedUse: 'enc',
  );
  return _RsaOaepPrivateKeyImpl(_importJwkRsa(k, isPrivateKey: true), hash);
}

Future<KeyPair<RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl>>
rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  HashImpl hash,
) async {
  return _generateRsaKeyPair(
    modulusLength,
    publicExponent,
    (k) => _RsaOaepPrivateKeyImpl(k, hash),
    (k) => _RsaOaepPublicKeyImpl(k, hash),
  );
}

Future<RsaOaepPublicKeyImpl> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  HashImpl hash,
) async {
  return _RsaOaepPublicKeyImpl(
    ssl.RsaKey.importSpki(Uint8List.fromList(keyData)),
    hash,
  );
}

Future<RsaOaepPublicKeyImpl> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash,
) async {
  final k = JsonWebKey.fromJson(jwk);
  final h = _HashImpl.fromHash(hash);

  _checkJwkRsa(
    k,
    isPrivateKey: false,
    expectedAlg: h.rsaOaepJwkAlg,
    expectedUse: 'enc',
  );
  return _RsaOaepPublicKeyImpl(_importJwkRsa(k, isPrivateKey: false), hash);
}

final class _StaticRsaOaepPrivateKeyImpl
    implements StaticRsaOaepPrivateKeyImpl {
  const _StaticRsaOaepPrivateKeyImpl();

  @override
  Future<RsaOaepPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) => rsaOaepPrivateKey_importPkcs8Key(keyData, hash);

  @override
  Future<RsaOaepPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) => rsaOaepPrivateKey_importJsonWebKey(jwk, hash);

  @override
  Future<(RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final keyPair = await rsaOaepPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
    return (keyPair.privateKey, keyPair.publicKey);
  }
}

final class _RsaOaepPrivateKeyImpl implements RsaOaepPrivateKeyImpl {
  final ssl.RsaKey _key;
  final HashImpl _hash;

  _RsaOaepPrivateKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaOaepPrivateKey\'';
  }

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label}) async {
    try {
      return ssl.RsaOaep.decrypt(
        _key,
        Uint8List.fromList(data),
        hash: _HashImpl.fromHash(_hash).hashName,
        label: label != null ? Uint8List.fromList(label) : null,
      );
    } catch (e) {
      throw operationError('RSA-OAEP decrypt failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final h = _HashImpl.fromHash(_hash);
    return _exportJwkRsa(
      _key,
      isPrivateKey: true,
      jwkAlg: h.rsaOaepJwkAlg,
      jwkUse: 'enc',
    );
  }

  @override
  Future<Uint8List> exportPkcs8Key() async => _key.exportPkcs8();
}

final class _StaticRsaOaepPublicKeyImpl implements StaticRsaOaepPublicKeyImpl {
  const _StaticRsaOaepPublicKeyImpl();

  @override
  Future<RsaOaepPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) => rsaOaepPublicKey_importSpkiKey(keyData, hash);

  @override
  Future<RsaOaepPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) => rsaOaepPublicKey_importJsonWebKey(jwk, hash);
}

final class _RsaOaepPublicKeyImpl implements RsaOaepPublicKeyImpl {
  final ssl.RsaKey _key;
  final HashImpl _hash;

  _RsaOaepPublicKeyImpl(this._key, this._hash);

  @override
  String toString() {
    return 'Instance of \'RsaOaepPublicKey\'';
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label}) async {
    try {
      return ssl.RsaOaep.encrypt(
        _key,
        Uint8List.fromList(data),
        hash: _HashImpl.fromHash(_hash).hashName,
        label: label != null ? Uint8List.fromList(label) : null,
      );
    } catch (e) {
      throw operationError('RSA-OAEP encrypt failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    final h = _HashImpl.fromHash(_hash);
    return _exportJwkRsa(
      _key,
      isPrivateKey: false,
      jwkAlg: h.rsaOaepJwkAlg,
      jwkUse: 'enc',
    );
  }

  @override
  Future<Uint8List> exportSpkiKey() async => _key.exportSpki();
}
