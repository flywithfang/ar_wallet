import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart';

import 'package:crypto/crypto.dart';

final AR_keyLength = 4096;
final AR_publicExponent = BigInt.from(65537);

Uint8List decode_base64_binary(String base64) =>
    base64Url.decode(base64Url.normalize(base64));

String decodeBase64ToString(String base64) =>
    utf8.decode(decode_base64_binary(base64));

BigInt decodeBase64ToBigInt(String base64) =>
    bytes_to_bigint(decode_base64_binary(base64));

BigInt bytes_to_bigint(List<int> bytes) {
  var result = BigInt.zero;
  for (var i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

String encodeStringToBase64(String string) =>
    binary_to_base64url(utf8.encode(string));

String binary_to_base64url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

final _byteMask = BigInt.from(0xff);

Uint8List encodeBigIntToBytes(BigInt bigInt) {
  var size = (bigInt.bitLength + 7) >> 3;
  var l = Uint8List(size);
  for (var i = 0; i < size; i++) {
    l[size - i - 1] = (bigInt & _byteMask).toInt();
    bigInt = bigInt >> 8;
  }
  return l;
}

String bigint_to_base64url(BigInt bigInt) =>
    binary_to_base64url(encodeBigIntToBytes(bigInt));

BigInt ar_to_winston(String ar) {
  if (ar.startsWith('.') || ar.endsWith('.')) {
    throw ArgumentError('AR format is invalid.');
  }

  if (ar.contains('.')) {
    final decimalPoint = ar.lastIndexOf('.');
    ar = ar.substring(0, decimalPoint) +
        ar.substring(decimalPoint + 1, ar.length).padRight(12, '0');
  } else {
    // If the string does not contain a decimal point the AR value is at least 1.
    ar = ar + '000000000000';
  }

  return BigInt.parse(ar);
}

String winston_to_ar(BigInt winston) {
  var bit = winston.toString().padLeft(12, '0');

  // The Winston amount is less than 1 AR.
  if (bit.length == 12) {
    bit = '0.' + bit;
  } else {
    bit = bit.substring(0, bit.length - 12) +
        '.' +
        bit.substring(bit.length - 12, bit.length);
  }

  // Trim trailing zeroes.
  while (bit.endsWith('0')) {
    bit = bit.substring(0, bit.length - 1);

    if (bit.endsWith('.')) {
      bit = bit.substring(0, bit.length - 1);
      break;
    }
  }

  return bit;
}

/// Safely get the error from an Arweave HTTP response.
String getResponseError(Response res) {
  if (res.headers['Content-Type'] == 'application/json') {
    Map<String, dynamic> errJson = json.decode(res.body);

    if (errJson['data'] != null) {
      return errJson['data'] is Map
          ? errJson['data']['error']
          : errJson['data'];
    }
  }

  return res.body;
}



Uint8List createUint8ListFromString(String s) {
  var ret = Uint8List(s.length);
  for (var i = 0; i < s.length; i++) {
    ret[i] = s.codeUnitAt(i);
  }
  return ret;
}