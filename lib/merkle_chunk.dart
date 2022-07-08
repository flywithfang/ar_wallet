import 'dart:math' as math;
import 'dart:typed_data';


import 'package:crypto/crypto.dart';
import 'ar_utils.dart';

const MAX_CHUNK_SIZE = 256 * 1024;
const HASH_SIZE = 32;
const NOTE_SIZE = 32;


class ChunkProof {
  final int offset; 
  final Uint8List chunk_path;

  ChunkProof(this.offset, this.chunk_path);
}

class ChunkMark {
  final Uint8List chunk_hash;
  final int end;

  ChunkMark(this.chunk_hash,  this.end);

    Map<String,dynamic> toJson(){
      var m=<String,dynamic>{
        "chunk_hash":binary_to_base64url(chunk_hash),
        "end":end.toString(),
      };
      return m;
    }
}


abstract class _MerkleNode {
  final Uint8List id;
  final int end;

  _MerkleNode(this.id, this.end);
}

class _BranchNode extends _MerkleNode {
  final  int left_end;
  final _MerkleNode left;
  final _MerkleNode right;

  _BranchNode(Uint8List id,this.left_end,int end,this.left,this.right): super(id, end);
}

class _LeafNode extends _MerkleNode {
  final List<int> chunk_hash;

  _LeafNode({required Uint8List id,required this.chunk_hash, required int end}): super(id, end);
}

List<ChunkMark> data_to_chunks(Uint8List data)  {
  final chunks = <ChunkMark>[];

  var rest = data;
  var cursor = 0;

  while (rest.lengthInBytes >= MAX_CHUNK_SIZE) {
    var chunkSize = MAX_CHUNK_SIZE;

    // If the total bytes left will produce a chunk < MIN_CHUNK_SIZE,
    // then adjust the amount we put in this 2nd last chunk.
    var nextChunkSize = rest.lengthInBytes - MAX_CHUNK_SIZE;
   
    final chunk = Uint8List.sublistView(rest, 0, chunkSize);
    if(chunk.length!=chunk.lengthInBytes) throw "bad length";
    cursor += chunk.length;
    chunks.add(ChunkMark(_sha256(chunk),cursor));
    rest = Uint8List.sublistView(rest, chunkSize);
  }
  if(rest.length>0)
    chunks.add(ChunkMark(_sha256(rest), cursor + rest.length));

  return chunks;
}


List<_LeafNode> generate_leaves(List<ChunkMark> chunks)  =>
      chunks.map((c) => _LeafNode(
              id: _sha256(_sha256(c.chunk_hash) + _sha256(_int_to_buf(c.end))),
              chunk_hash: c.chunk_hash,
              end: c.end,
            )).toList();

/// Starting with the bottom layer of leaf nodes, hash every second pair
/// into a new branch node, push those branch nodes onto a new layer,
/// and then recurse, building up the tree to it's root, where the
/// layer only consists of two items.
_MerkleNode generate_tree(List<_MerkleNode> nodes,[int level = 0])  {
  // If there are only 2 nodes left, this is going to be the root node
  if(nodes.length==0) throw "bad length";
  if (nodes.length == 1 ) {
      return nodes[0];
  }

  final nextLayer = <_MerkleNode>[];

  for (var i = 0; i < nodes.length; i += 2) {
    nextLayer.add( i + 1 < nodes.length ? mk_branch_node(nodes[i],  nodes[i + 1]):nodes[i]);
  }

  return generate_tree(nextLayer, level + 1);
}

_MerkleNode mk_branch_node(_MerkleNode left, _MerkleNode right)  {
  return _BranchNode( _sha256(_sha256(left.id) +_sha256(right.id) + _sha256(_int_to_buf(left.end))),
     left.end,
     right.end,
     left,
     right,
  );
}


/// Recursively search through all branches of the tree,
/// and generate a chunk_path for each leaf node.
List<ChunkProof> generate_proofs(_MerkleNode root) {
  final proofs = generate_all_leaf_path(root);

  print(proofs);

  List<dynamic> flatten(Iterable iter) => iter.fold([], (List xs, s) {
        s is Iterable ? xs.addAll(flatten(s)) : xs.add(s);
        return xs;
      });

  // Flatten the Merkle proofs.
  return flatten(proofs).cast<ChunkProof>().toList();
}

List<Object> generate_all_leaf_path(_MerkleNode node, [List<int>? chunk_path, depth = 0]) {
  chunk_path = chunk_path ?? <int>[];
  
  if (node is _LeafNode) {
      final proof=ChunkProof(
        node.end - 1,
        Uint8List.fromList(chunk_path + node.chunk_hash + _int_to_buf(node.end)),
      );
      print("path: ${proof.chunk_path.length}");
    return [proof    ];
  } else if (node is _BranchNode) {
    final partial_path = chunk_path +node.left.id +node.right.id +_int_to_buf(node.left_end);
    print("partial_path: ${partial_path.length}");
    return [
      
      generate_all_leaf_path(node.left, partial_path, depth + 1),
      generate_all_leaf_path(node.right, partial_path, depth + 1),
    ];
  }

  throw ArgumentError('Unexpected node type');
}

class  ValidatePathRet{
  bool valid=false;
  int? end;
  ValidatePathRet(this.valid,this.end);
}
ValidatePathRet validate_path(Uint8List data_root, int chunk_offset, Uint8List path) {
  if(chunk_offset<0) return ValidatePathRet(false,null);


  return __validate_path(data_root,chunk_offset,path);
}
ValidatePathRet __validate_path(Uint8List id, int chunk_offset,Uint8List path)  {
  print("path size:${path.length},${path.lengthInBytes}");
  if (path.length == HASH_SIZE + NOTE_SIZE) {
    final chunk_hash = Uint8List.sublistView(path, 0, HASH_SIZE);
    final leaf_end_bin = Uint8List.sublistView(path, chunk_hash.length, chunk_hash.length + NOTE_SIZE);

    final leaf_hash = _sha256(_sha256(chunk_hash) + _sha256(leaf_end_bin),
    );
    final leaf_end=_buf_to_int(leaf_end_bin);

    return ValidatePathRet(binary_is_equal(id, leaf_hash) && chunk_offset<leaf_end,leaf_end);
  }

  final left = Uint8List.sublistView(path, 0, HASH_SIZE);

  if(left.length!=HASH_SIZE) throw "bad size ${left.length}";

  final right = Uint8List.sublistView(path, left.length, left.length + HASH_SIZE);
  final left_end_bin = Uint8List.sublistView(path, left.length + right.length, left.length + right.length + NOTE_SIZE);
  final left_end = _buf_to_int(left_end_bin);

  final rest_path = Uint8List.sublistView(path, left.length + right.length + left_end_bin.length);

  final id2 =  _sha256(_sha256(left) +  _sha256(right) +  _sha256(left_end_bin));

  if (binary_is_equal(id, id2)) {
    if (chunk_offset < left_end) {
      return __validate_path(left, chunk_offset, rest_path);
    }else
      return __validate_path(right, chunk_offset, rest_path);
  }
  else
      return ValidatePathRet(false,left_end);
}

Uint8List _sha256(List<int> data)  {
  final hash = sha256.convert(data);
  return Uint8List.fromList(hash.bytes);
}

bool binary_is_equal(Uint8List a, Uint8List b) {
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

int _buf_to_int(Uint8List buffer) {
  var value = 0;

  for (var i = 0; i < buffer.length; i++) {
    value *= 256;
    value += buffer[i];
  }

  return value;
}

Uint8List _int_to_buf(int note) {
  final buffer = Uint8List(NOTE_SIZE);

  for (var i = buffer.length - 1; i >= 0; i--) {
    var byte = note % 256;
    buffer[i] = byte;
    note = (note - byte) ~/ 256;
  }

  return buffer;
}
