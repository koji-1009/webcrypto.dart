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

part of 'impl_interface.dart';

abstract interface class StaticHmacSecretKeyImpl {
  Future<HmacSecretKeyImpl> importRawKey(List<int> keyData, HashImpl hash,
      {int? length});
  Future<HmacSecretKeyImpl> importJsonWebKey(
      Map<String, dynamic> jwk, HashImpl hash,
      {int? length});
  Future<HmacSecretKeyImpl> generateKey(HashImpl hash, {int? length});
}

abstract interface class HmacSecretKeyImpl {
  Future<Uint8List> signBytes(List<int> data);
  Future<bool> verifyBytes(List<int> signature, List<int> data);
  Future<Uint8List> signStream(Stream<List<int>> data);
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data);
  Future<Uint8List> exportRawKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
