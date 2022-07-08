import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

Uint8List deep_hash(List<Object> data)  {
  final tag = utf8.encode('list') + utf8.encode(data.length.toString());
  return _deepHashChunks(
    data,
    _sha384(tag),
  );
}

Uint8List _deepHashChunks(Iterable<Object> chunks, Uint8List acc)  {
  // If we're at the end of the chunks list, return.
  if (chunks.isEmpty) return acc;

  Object head=chunks.first;
  final hashPair = acc +
      // If the current chunk is not a byte list, we assume it's a nested byte list.
      (head is! Uint8List ?  deep_hash(head as List<Object>) :  _deepHashChunk(head as Uint8List));

  final newAcc = _sha384(hashPair);
  return _deepHashChunks(chunks.skip(1), newAcc);
}

Uint8List _deepHashChunk(Uint8List data)  {
  final tag = utf8.encode('blob') + utf8.encode(data.lengthInBytes.toString());
  final taggedHash =  _sha384(tag) +  _sha384(data);
  return _sha384(taggedHash);
}

Uint8List _sha384(List<int> data)  {
  final digest =  sha384.convert(data);
  return Uint8List.fromList(digest.bytes);
}