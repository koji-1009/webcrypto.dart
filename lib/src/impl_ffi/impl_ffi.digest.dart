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
  const _HashImpl();

  factory _HashImpl.fromHash(HashImpl hash) {
    if (hash is _HashImpl) {
      return hash;
    }
    throw AssertionError(
        'Custom implementations of HashImpl are not supported.');
  }

  @protected
  ffi.Pointer<EVP_MD> Function() get _algorithm;

  /// Get an instantiated [EVP_MD] for this hash algorithm.
  ffi.Pointer<EVP_MD> get _md {
    final md = _algorithm();
    _checkOp(md.address != 0, fallback: 'failed to instantiate hash algorithm');
    return md;
  }

  @override
  Future<Uint8List> digestBytes(List<int> data) =>
      digestStream(Stream.value(data));

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) {
    return _Scope.async((scope) async {
      final ctx = scope.create(ssl.EVP_MD_CTX_new, ssl.EVP_MD_CTX_free);
      // Initialize with hash function
      _checkOp(ssl.EVP_DigestInit(ctx, _md) == 1);

      // Stream data
      await _streamToUpdate(data, ctx, ssl.EVP_DigestUpdate);

      // Get size of the output buffer
      final size = ssl.EVP_MD_CTX_size(ctx);
      _checkOp(size > 0); // sanity check

      // Allocate output buffer and return output
      final out = scope<ffi.Uint8>(size);
      _checkOp(ssl.EVP_DigestFinal(ctx, out, ffi.nullptr) == 1);
      return out.copy(size);
    });
  }

  /// Algorithm (`alg` for JWK) when this hash algorithm is used in an HMAC.
  ///
  /// For SHA-1, it returns 'HS1'.
  /// For SHA-256, it returns 'HS256'.
  /// For SHA-384, it returns 'HS384'.
  /// For SHA-512, it returns 'HS512'.
  ///
  /// See canonical registry in:
  /// https://www.iana.org/assignments/jose/jose.xhtml
  String get hmacJwkAlg;

  /// Algorithm (`alg` for JWK) when this hash algorithm is used in RSA-OAEP.
  ///
  /// For SHA-1, it returns 'RSA-OAEP-1'.
  /// For SHA-256, it returns 'RSA-OAEP-256'.
  /// For SHA-384, it returns 'RSA-OAEP-384'.
  /// For SHA-512, it returns 'RSA-OAEP-512'.
  ///
  /// See canonical registry in:
  /// https://www.iana.org/assignments/jose/jose.xhtml
  String get rsaOaepJwkAlg;

  /// Algorithm (`alg` for JWK) when this hash algorithm is used in RSA-PSS.
  ///
  /// For SHA-1, it returns 'PS1'.
  /// For SHA-256, it returns 'PS256'.
  /// For SHA-384, it returns 'PS384'.
  /// For SHA-512, it returns 'PS512'.
  ///
  /// See canonical registry in:
  /// https://www.iana.org/assignments/jose/jose.xhtml
  String get rsaPssJwkAlg;

  /// Algorithm (`alg` for JWK) when this hash algorithm is used in RSASSA-PKCS1-v1_5.
  ///
  /// For SHA-1, it returns 'RS1'.
  /// For SHA-256, it returns 'RS256'.
  /// For SHA-384, it returns 'RS384'.
  /// For SHA-512, it returns 'RS512'.
  ///
  /// See canonical registry in:
  /// https://www.iana.org/assignments/jose/jose.xhtml
  String get rsassaPkcs1V15JwkAlg;
}

final class _Sha1 extends _HashImpl {
  const _Sha1();

  @override
  String get hmacJwkAlg => 'HS1';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-1';

  @override
  String get rsaPssJwkAlg => 'PS1';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS1';

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha1;
}

final class _Sha256 extends _HashImpl {
  const _Sha256();

  @override
  String get hmacJwkAlg => 'HS256';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-256';

  @override
  String get rsaPssJwkAlg => 'PS256';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS256';

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha256;
}

final class _Sha384 extends _HashImpl {
  const _Sha384();

  @override
  String get hmacJwkAlg => 'HS384';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-384';

  @override
  String get rsaPssJwkAlg => 'PS384';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS384';

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha384;
}

final class _Sha512 extends _HashImpl {
  const _Sha512();

  @override
  String get hmacJwkAlg => 'HS512';

  @override
  String get rsaOaepJwkAlg => 'RSA-OAEP-512';

  @override
  String get rsaPssJwkAlg => 'PS512';

  @override
  String get rsassaPkcs1V15JwkAlg => 'RS512';

  @override
  ffi.Pointer<EVP_MD> Function() get _algorithm => ssl.EVP_sha512;
}

// Note: Before adding new hash implementations, make sure to update all the
//       places that does if (hash == HashImpl.shaXXX) ...
