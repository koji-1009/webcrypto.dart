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

Future<AesCbcSecretKeyImpl> aesCbc_importRawKey(List<int> keyData) async =>
    _AesCbcSecretKeyImpl(_aesImportRawKey(keyData));

Future<AesCbcSecretKeyImpl> aesCbc_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesCbcSecretKeyImpl(_aesImportJwkKey(jwk, expectedJwkAlgSuffix: 'CBC'));

Future<AesCbcSecretKeyImpl> aesCbc_generateKey(int length) async =>
    _AesCbcSecretKeyImpl(_aesGenerateKey(length));

final class _StaticAesCbcSecretKeyImpl implements StaticAesCbcSecretKeyImpl {
  const _StaticAesCbcSecretKeyImpl();

  @override
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData) async {
    return await aesCbc_importRawKey(keyData);
  }

  @override
  Future<AesCbcSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    return await aesCbc_importJsonWebKey(jwk);
  }

  @override
  Future<AesCbcSecretKeyImpl> generateKey(int length) async {
    return await aesCbc_generateKey(length);
  }
}

final class _AesCbcSecretKeyImpl implements AesCbcSecretKeyImpl {
  final Uint8List _key;
  _AesCbcSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'AesCbcSecretKey\'';
  }

  @override
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv) async {
    try {
      return ssl.AesCbc.decrypt(
        _key,
        Uint8List.fromList(iv),
        Uint8List.fromList(data),
      );
    } catch (e) {
      throw operationError('AES-CBC decrypt failed: $e');
    }
  }

  @override
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv) async* {
    final ctx = ssl.AesCbc.startDecrypt(_key, Uint8List.fromList(iv));
    try {
      await for (final chunk in data) {
        yield ctx.update(Uint8List.fromList(chunk));
      }
      yield ctx.finish();
    } catch (e) {
      throw operationError('AES-CBC decrypt stream failed: $e');
    }
  }

  @override
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv) async {
    return ssl.AesCbc.encrypt(
      _key,
      Uint8List.fromList(iv),
      Uint8List.fromList(data),
    );
  }

  @override
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv) async* {
    final ctx = ssl.AesCbc.startEncrypt(_key, Uint8List.fromList(iv));
    await for (final chunk in data) {
      yield ctx.update(Uint8List.fromList(chunk));
    }
    yield ctx.finish();
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'CBC');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}
