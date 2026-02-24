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

Future<AesGcmSecretKeyImpl> aesGcm_importRawKey(List<int> keyData) async =>
    _AesGcmSecretKeyImpl(_aesImportRawKey(keyData));

Future<AesGcmSecretKeyImpl> aesGcm_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesGcmSecretKeyImpl(_aesImportJwkKey(jwk, expectedJwkAlgSuffix: 'GCM'));

Future<AesGcmSecretKeyImpl> aesGcm_generateKey(int length) async =>
    _AesGcmSecretKeyImpl(_aesGenerateKey(length));

final class _StaticAesGcmSecretKeyImpl implements StaticAesGcmSecretKeyImpl {
  const _StaticAesGcmSecretKeyImpl();

  @override
  Future<AesGcmSecretKeyImpl> importRawKey(List<int> keyData) async {
    return await aesGcm_importRawKey(keyData);
  }

  @override
  Future<AesGcmSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    return await aesGcm_importJsonWebKey(jwk);
  }

  @override
  Future<AesGcmSecretKeyImpl> generateKey(int length) async {
    return await aesGcm_generateKey(length);
  }
}

final class _AesGcmSecretKeyImpl implements AesGcmSecretKeyImpl {
  final Uint8List _key;
  _AesGcmSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'AesGcmSecretKey\'';
  }

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async {
    try {
      final tLenBits = tagLength ?? 128;
      if (tLenBits % 8 != 0) {
        throw ArgumentError('tagLength must be multiple of 8');
      }
      // boringssl_dart expects bytes
      final tLenBytes = tLenBits ~/ 8;

      return ssl.AesGcm.decrypt(
        _key,
        Uint8List.fromList(iv),
        Uint8List.fromList(data),
        additionalData: additionalData != null
            ? Uint8List.fromList(additionalData)
            : null,
        tagLength: tLenBytes,
      );
    } catch (e) {
      throw operationError('AES-GCM decrypt failed: $e');
    }
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int>? additionalData,
    int? tagLength = 128,
  }) async {
    try {
      if (data.length > (1 << 39) - 256) {
        throw operationError('data may not be more than 2^39 - 256 bytes');
      }
      final tLenBits = tagLength ?? 128;
      if (tLenBits % 8 != 0) {
        throw ArgumentError('tagLength must be multiple of 8');
      }
      final tLenBytes = tLenBits ~/ 8;

      return ssl.AesGcm.encrypt(
        _key,
        Uint8List.fromList(iv),
        Uint8List.fromList(data),
        additionalData: additionalData != null
            ? Uint8List.fromList(additionalData)
            : null,
        tagLength: tLenBytes,
      );
    } catch (e) {
      if (e is ArgumentError || e is OperationError) {
        rethrow;
      }
      throw operationError('AES-GCM encrypt failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'GCM');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}
