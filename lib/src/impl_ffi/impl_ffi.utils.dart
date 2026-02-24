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

Uint8List _asUint8ListZeroedToBitLength(List<int> data, [int? lengthInBits]) {
  final buf = Uint8List.fromList(data);
  if (lengthInBits != null) {
    final startFrom = (lengthInBits / 8).floor();
    var remainder = (lengthInBits % 8).toInt();
    for (var i = startFrom; i < buf.length; i++) {
      final mask = 0xff & (0xff << (8 - remainder));
      buf[i] = buf[i] & mask;
      remainder = 8;
    }
  }
  return buf;
}

Uint8List _jwkDecodeBase64UrlNoPadding(String data, String prop) {
  try {
    return base64Url.decode(base64Url.normalize(data));
  } on FormatException {
    throw FormatException(
      'JWK property "$prop" is not url-safe base64 without padding',
      data,
    );
  }
}

String _jwkEncodeBase64UrlNoPadding(List<int> data) {
  return base64Url.encode(data).replaceAll('=', '');
}
