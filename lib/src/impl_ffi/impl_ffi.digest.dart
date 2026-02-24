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

abstract class _HashImpl implements HashImpl {
  final ssl.Hash _algo;
  const _HashImpl(this._algo);

  factory _HashImpl.fromHash(HashImpl hash) {
    if (hash is _HashImpl) {
      return hash;
    }
    throw AssertionError(
      'Custom implementations of HashImpl are not supported.',
    );
  }

  @override
  Future<Uint8List> digestBytes(List<int> data) async {
    return _algo.digest(data);
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    final ctx = _algo.start();
    await for (final chunk in data) {
      ctx.update(chunk);
    }
    return ctx.finish();
  }

  String get hmacJwkAlg;
  String get rsaOaepJwkAlg;
  String get rsaPssJwkAlg;
  String get rsassaPkcs1V15JwkAlg;

  String get hashName;
  int get digestLength;
}

final class _Sha1 extends _HashImpl {
  const _Sha1() : super(ssl.Hash.sha1);

  @override
  String get hashName => 'SHA-1';

  @override
  int get digestLength => 20;

  @override
  String get hmacJwkAlg => 'HS1';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-1';

  @override
  String get rsaPssJwkAlg => 'PS1';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS1';
}

final class _Sha256 extends _HashImpl {
  const _Sha256() : super(ssl.Hash.sha256);

  @override
  String get hashName => 'SHA-256';

  @override
  int get digestLength => 32;

  @override
  String get hmacJwkAlg => 'HS256';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-256';

  @override
  String get rsaPssJwkAlg => 'PS256';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS256';
}

final class _Sha384 extends _HashImpl {
  const _Sha384() : super(ssl.Hash.sha384);

  @override
  String get hashName => 'SHA-384';

  @override
  int get digestLength => 48;

  @override
  String get hmacJwkAlg => 'HS384';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-384';

  @override
  String get rsaPssJwkAlg => 'PS384';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS384';
}

final class _Sha512 extends _HashImpl {
  const _Sha512() : super(ssl.Hash.sha512);

  @override
  String get hashName => 'SHA-512';

  @override
  int get digestLength => 64;

  @override
  String get hmacJwkAlg => 'HS512';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-512';

  @override
  String get rsaPssJwkAlg => 'PS512';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS512';
}
