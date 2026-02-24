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

Future<HmacSecretKeyImpl> hmacSecretKey_importRawKey(
  List<int> keyData,
  HashImpl hash, {
  int? length,
}) async {
  return _HmacSecretKeyImpl(
    _asUint8ListZeroedToBitLength(keyData, length),
    _HashImpl.fromHash(hash),
  );
}

Future<HmacSecretKeyImpl> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  HashImpl hash, {
  int? length,
}) async {
  final h = _HashImpl.fromHash(hash);
  final k = JsonWebKey.fromJson(jwk);

  void checkJwk(bool condition, String prop, String message) {
    if (!condition) throw FormatException('JWK property "$prop" $message');
  }

  checkJwk(k.kty == 'oct', 'kty', 'must be "oct"');
  checkJwk(k.k != null, 'k', 'must be present');
  checkJwk(k.use == null || k.use == 'sig', 'use', 'must be "sig", if present');
  final expectedAlg = h.hmacJwkAlg;
  checkJwk(
    k.alg == null || k.alg == expectedAlg,
    'alg',
    'must be "$expectedAlg"',
  );

  final keyData = _jwkDecodeBase64UrlNoPadding(k.k!, 'k');

  return hmacSecretKey_importRawKey(keyData, hash, length: length);
}

Future<HmacSecretKeyImpl> hmacSecretKey_generateKey(
  HashImpl hash, {
  int? length,
}) async {
  final h = _HashImpl.fromHash(hash);
  length ??= h.digestLength * 8;

  final keyData = Uint8List((length / 8).ceil());
  ssl.getRandomValues(keyData);

  return _HmacSecretKeyImpl(_asUint8ListZeroedToBitLength(keyData, length), h);
}

final class _StaticHmacSecretKeyImpl implements StaticHmacSecretKeyImpl {
  const _StaticHmacSecretKeyImpl();

  @override
  Future<HmacSecretKeyImpl> importRawKey(
    List<int> keyData,
    HashImpl hash, {
    int? length,
  }) {
    return hmacSecretKey_importRawKey(keyData, hash, length: length);
  }

  @override
  Future<HmacSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash, {
    int? length,
  }) {
    return hmacSecretKey_importJsonWebKey(jwk, hash, length: length);
  }

  @override
  Future<HmacSecretKeyImpl> generateKey(HashImpl hash, {int? length}) {
    return hmacSecretKey_generateKey(hash, length: length);
  }
}

final class _HmacSecretKeyImpl implements HmacSecretKeyImpl {
  final _HashImpl _hash;
  final Uint8List _keyData;

  _HmacSecretKeyImpl(this._keyData, this._hash);

  @override
  String toString() {
    return 'Instance of \'HmacSecretKeyImpl\'';
  }

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return ssl.Hmac.sign(_keyData, Uint8List.fromList(data), _hash.hashName);
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    final signer = ssl.HmacSigner(_keyData, _hash.hashName);
    await for (final chunk in data) {
      signer.update(Uint8List.fromList(chunk));
    }
    return signer.finish();
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return ssl.Hmac.verify(
      _keyData,
      Uint8List.fromList(signature),
      Uint8List.fromList(data),
      _hash.hashName,
    );
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    final computed = await signStream(data);
    return ssl.constantTimeEq(Uint8List.fromList(signature), computed);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'oct',
      use: 'sig',
      alg: _hash.hmacJwkAlg,
      k: _jwkEncodeBase64UrlNoPadding(_keyData),
    ).toJson();
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return Uint8List.fromList(_keyData);
  }
}
