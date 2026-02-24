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

Future<AesCtrSecretKeyImpl> aesCtr_importRawKey(List<int> keyData) async =>
    _AesCtrSecretKeyImpl(_aesImportRawKey(keyData));

Future<AesCtrSecretKeyImpl> aesCtr_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesCtrSecretKeyImpl(_aesImportJwkKey(jwk, expectedJwkAlgSuffix: 'CTR'));

Future<AesCtrSecretKeyImpl> aesCtr_generateKey(int length) async =>
    _AesCtrSecretKeyImpl(_aesGenerateKey(length));

BigInt _parseBigEndian(List<int> data, [int? bitLength]) {
  bitLength ??= data.length * 8;
  assert(bitLength <= data.length * 8);

  final init = data.length - (bitLength / 8).ceil();
  final remainderBits = bitLength % 8;

  var copy = data;
  if (remainderBits != 0) {
    copy = Uint8List.fromList(data);
    copy[init] &= ~(0xff << remainderBits);
  }

  var value = BigInt.from(0);
  for (var i = init; i < copy.length; i++) {
    value = (value << 8) | BigInt.from(copy[i] & 0xff);
  }
  return value;
}

Stream<Uint8List> _aesCtrEncryptOrDecrypt(
  Uint8List key,
  bool encrypt,
  Stream<List<int>> source,
  List<int> counter,
  int length,
) async* {
  assert(counter.length == 16);
  const blockSize = 16;

  final ctrValues = BigInt.one << length;
  final ctr = _parseBigEndian(counter, length);

  var bytesUntilWraparound = (ctrValues - ctr) * BigInt.from(blockSize);
  var bytesAfterWraparound = ctr * BigInt.from(blockSize);

  // Initialize context
  // Use Uint8List.fromList to ensure we have a copy if needed, though AesCtr copies internally usually.
  var ctx = encrypt
      ? ssl.AesCtr.startEncrypt(key, Uint8List.fromList(counter))
      : ssl.AesCtr.startDecrypt(key, Uint8List.fromList(counter));

  var isBeforeWrapAround = true;

  await for (final chunk in source) {
    var offset = 0;
    final len = chunk.length;
    while (offset < len) {
      int M;
      if (isBeforeWrapAround) {
        M = math.min(bytesUntilWraparound.toInt(), chunk.length - offset);
        bytesUntilWraparound -= BigInt.from(M);
      } else {
        M = chunk.length - offset;
        if (bytesAfterWraparound.toInt() < M) {
          throw const FormatException(
            'input is too large for the counter length',
          );
        }
        bytesAfterWraparound -= BigInt.from(M);
      }

      final part = chunk.sublist(offset, offset + M);
      yield ctx.update(Uint8List.fromList(part));
      offset += M;

      if (isBeforeWrapAround && bytesUntilWraparound == BigInt.zero) {
        yield ctx.finish();

        final c = Uint8List.fromList(counter);
        final legacyCounterBytes = length ~/ 8;
        c.fillRange(16 - legacyCounterBytes, 16, 0);
        final remainderBits = length % 8;
        if (remainderBits != 0) {
          c[16 - legacyCounterBytes - 1] &= 0xff & (0xff << remainderBits);
        }

        ctx = encrypt
            ? ssl.AesCtr.startEncrypt(key, c)
            : ssl.AesCtr.startDecrypt(key, c);
        isBeforeWrapAround = false;
      }
    }
  }
  yield ctx.finish();
}

final class _StaticAesCtrSecretKeyImpl implements StaticAesCtrSecretKeyImpl {
  const _StaticAesCtrSecretKeyImpl();

  @override
  Future<AesCtrSecretKeyImpl> importRawKey(List<int> keyData) async {
    return await aesCtr_importRawKey(keyData);
  }

  @override
  Future<AesCtrSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) async {
    return await aesCtr_importJsonWebKey(jwk);
  }

  @override
  Future<AesCtrSecretKeyImpl> generateKey(int length) async {
    return await aesCtr_generateKey(length);
  }
}

final class _AesCtrSecretKeyImpl implements AesCtrSecretKeyImpl {
  final Uint8List _key;
  _AesCtrSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'AesCtrSecretKey\'';
  }

  void _checkArguments(List<int> counter, int length) {
    if (counter.length != 16) {
      throw ArgumentError.value(counter, 'counter', 'must be 16 bytes');
    }
    if (length <= 0 || 128 < length) {
      throw ArgumentError.value(length, 'length', 'must be between 1 and 128');
    }
  }

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    try {
      _checkArguments(counter, length);
      final stream = decryptStream(Stream.value(data), counter, length);
      final chunks = await stream.toList();
      if (chunks.isEmpty) return Uint8List(0);
      if (chunks.length == 1) return chunks.first;
      final total = chunks.fold(0, (sum, c) => sum + c.length);
      final res = Uint8List(total);
      var offset = 0;
      for (final c in chunks) {
        res.setAll(offset, c);
        offset += c.length;
      }
      return res;
    } catch (e) {
      throw operationError('AES-CTR decrypt failed: $e');
    }
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    try {
      _checkArguments(counter, length);
      return _aesCtrEncryptOrDecrypt(_key, false, data, counter, length);
    } catch (e) {
      throw operationError('AES-CTR decrypt failed: $e');
    }
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    try {
      _checkArguments(counter, length);
      final stream = encryptStream(Stream.value(data), counter, length);
      final chunks = await stream.toList();
      if (chunks.isEmpty) return Uint8List(0);
      if (chunks.length == 1) return chunks.first;
      final total = chunks.fold(0, (sum, c) => sum + c.length);
      final res = Uint8List(total);
      var offset = 0;
      for (final c in chunks) {
        res.setAll(offset, c);
        offset += c.length;
      }
      return res;
    } catch (e) {
      throw operationError('AES-CTR encrypt failed: $e');
    }
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    try {
      _checkArguments(counter, length);
      return _aesCtrEncryptOrDecrypt(_key, true, data, counter, length);
    } catch (e) {
      throw operationError('AES-CTR encrypt failed: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'CTR');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}
