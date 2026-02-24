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

String _ecCurveName(EllipticCurve curve) {
  return switch (curve) {
    EllipticCurve.p256 => 'P-256',
    EllipticCurve.p384 => 'P-384',
    EllipticCurve.p521 => 'P-521',
  };
}

// Helpers for Jwk import validation
void _checkJwkEc(
  JsonWebKey jwk, {
  required bool isPrivateKey,
  required String expectedUse,
  required String curveName,
  String? expectedAlg,
}) {
  if (jwk.kty != 'EC') {
    throw const FormatException('JWK "kty" must be "EC"');
  }
  if (jwk.x == null || jwk.y == null) {
    throw const FormatException('JWK "x" and "y" must be present');
  }
  if (isPrivateKey && jwk.d == null) {
    throw const FormatException('JWK "d" must be present for private keys');
  }
  if (!isPrivateKey && jwk.d != null) {
    throw const FormatException('JWK "d" must not be present for public keys');
  }
  if (jwk.crv != curveName) {
    throw FormatException('JWK "crv" must be "$curveName"');
  }
  if (expectedAlg != null && jwk.alg != null && jwk.alg != expectedAlg) {
    throw FormatException('JWK "alg" must be "$expectedAlg"');
  }
  if (jwk.use != null && jwk.use != expectedUse) {
    throw FormatException('JWK "use" must be "$expectedUse"');
  }
}

ssl.EcKey _importJwkEc(
  JsonWebKey jwk,
  EllipticCurve curve, {
  required bool isPrivateKey,
}) {
  final curveName = _ecCurveName(curve);

  // Decoding helpers
  Uint8List decode(String val, String prop) =>
      _jwkDecodeBase64UrlNoPadding(val, prop);

  return ssl.EcKey.importCoordinates(
    curve: curveName,
    x: decode(jwk.x!, 'x'),
    y: decode(jwk.y!, 'y'),
    d: isPrivateKey ? decode(jwk.d!, 'd') : null,
  );
}

Map<String, dynamic> _exportJwkEc(
  ssl.EcKey key, {
  required bool isPrivateKey,
  required String jwkUse,
}) {
  final coords = key.exportCoordinates();
  // coords has x, y, (d) as Uint8List

  return JsonWebKey(
    kty: 'EC',
    use: jwkUse,
    crv: key.curve, // EcKey stores 'P-256' etc.
    x: _jwkEncodeBase64UrlNoPadding(coords['x']!),
    y: _jwkEncodeBase64UrlNoPadding(coords['y']!),
    d: isPrivateKey ? _jwkEncodeBase64UrlNoPadding(coords['d']!) : null,
  ).toJson();
}
