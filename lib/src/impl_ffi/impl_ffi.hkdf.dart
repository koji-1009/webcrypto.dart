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

Future<HkdfSecretKeyImpl> hkdfSecretKey_importRawKey(List<int> keyData) async =>
    _HkdfSecretKeyImpl(Uint8List.fromList(keyData));

final class _StaticHkdfSecretKeyImpl implements StaticHkdfSecretKeyImpl {
  const _StaticHkdfSecretKeyImpl();

  @override
  Future<HkdfSecretKeyImpl> importRawKey(List<int> keyData) async {
    return hkdfSecretKey_importRawKey(keyData);
  }
}

final class _HkdfSecretKeyImpl implements HkdfSecretKeyImpl {
  final Uint8List _key;

  _HkdfSecretKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'HkdfSecretKey\'';
  }

  @override
  Future<Uint8List> deriveBits(
    int length,
    HashImpl hash,
    List<int> salt,
    List<int> info,
  ) async {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be positive integer');
    }
    // Mirroring limitations in chromium/legacy code:
    if (length % 8 != 0) {
      throw operationError('The length for HKDF must be a multiple of 8 bits');
    }

    final lengthInBytes = length ~/ 8;
    final h = _HashImpl.fromHash(hash);

    try {
      return ssl.Hkdf.derive(
        key: _key,
        salt: Uint8List.fromList(salt),
        info: Uint8List.fromList(info),
        length: lengthInBytes,
        hashAlgorithm: h.hashName,
      );
    } on ArgumentError catch (e) {
      // Convert specific boringssl error if needed (HKDF output too large) to OperationError?
      // Legacy code threw OperationError on HKDF_R_OUTPUT_TOO_LARGE.
      // boringssl_dart throws ArgumentError('HKDF output length too large').
      if (e.message == 'HKDF output length too large') {
        throw operationError(
          'Length specified for HkdfSecretKey.deriveBits is too long',
        );
      }
      rethrow;
    } catch (e) {
      throw operationError('HKDF deriveBits failed: $e');
    }
  }
}
