
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:ar_wallet/ar_deep_hash.dart';
import 'package:ar_wallet/ar_type.dart';
import 'package:ar_wallet/rsa_pss.dart';
import 'package:ar_wallet/ar_utils.dart';
import 'dart:typed_data';
import 'merkle_chunk.dart' as merkle;


class Tag{
	String name="";
	String value="";

	Tag(this.name,this.value);
	
	Map<String, dynamic> toJson() =>
      {'name': this.name, 'value': this.value};

}
class ARTx{
	int format=2;
	String id="";
	String last_tx="";
	String owner="";
	List<Tag> tags=[];
	String target="";
	String quantity="";
	String data_root="";
	String data_size="0";
	Uint8List data=Uint8List(0);
	String reward="";
	String signature="";

	 List<merkle.ChunkMark> chunk_marks=<merkle.ChunkMark>[];
   List<merkle.ChunkProof> proofs=<merkle.ChunkProof>[];

	Future<void> init_transfer(Account acc,addr,int amount,String tx_anchor,int fee,{int? format})async{
		
		assert(tx_anchor.length>0);
		assert(fee>0);
		assert(amount>0);

		this.owner=acc.get_pub_key_base64url();
		this.target=addr;
		this.quantity = amount.toString();
		this.last_tx=tx_anchor;
		this.reward=fee.toString();
		this.format=format??2;
		
	
	}
	Future<void> sign(Account acc)async{
		if(this.signature.length>0) throw "signed";

		final message=get_sign_data();

		final sign =await rsa_pss_sign(message:message,kp:acc.kp);

		this.signature=binary_to_base64url(sign);

		this.id=binary_to_base64url(sha256.convert(sign).bytes);

	  /// Constructs a [Transaction] with the specified blob data and computed data size.
	}

	Future<void> init_upload(Account acc,String tx_anchor,int fee,Uint8List data)async{
		
		assert(tx_anchor.length>0);
		assert(fee>0);

		this.owner=acc.get_pub_key_base64url();
		this.target="";
		this.quantity = "0";
		this.last_tx=tx_anchor;
		this.reward=fee.toString();
		this.format=2;

		if(data.length==0) throw "bad data";
		__set_data(data);
	

	}
	void add_tag(String name,String val){
		tags.add(Tag(name,val));
	}

	Future<bool> verify_sign()async {
		final message=get_sign_data();

		final sign =decode_base64_binary(this.signature);

		
		final sign_valid=await rsa_pss_verify( message:message,signature:sign,e:AR_publicExponent,n:bytes_to_bigint(decode_base64_binary(this.owner)));
		
		return sign_valid;
	}
	Uint8List get_sign_data(){
				/*
				* ar_deep_hash:hash([
		<<(integer_to_binary(TX#tx.format))/binary>>,
		<<(TX#tx.owner)/binary>>,
		<<(TX#tx.target)/binary>>,
		<<(list_to_binary(integer_to_list(TX#tx.quantity)))/binary>>,
		<<(list_to_binary(integer_to_list(TX#tx.reward)))/binary>>,
		<<(TX#tx.last_tx)/binary>>,
		tags_to_list(TX#tx.tags),
		<<(integer_to_binary(TX#tx.data_size))/binary>>,
		<<(TX#tx.data_root)/binary>>
	]).
	*/
				//format, owner, target, data_root, data_size, quantity, reward, last_tx, tags
				List<Object> l=[
				utf8.encode(this.format.toString()),
				decode_base64_binary(this.owner),
				decode_base64_binary(this.target),
				
				utf8.encode(this.quantity),
				utf8.encode(this.reward),
				decode_base64_binary(this.last_tx),
				this.tags.map(
	                (t) => [
	                  utf8.encode(t.name),
	                  utf8.encode(t.value),
	                ],
	              ).toList(),

				utf8.encode(this.data_size),
				decode_base64_binary(this.data_root),
				];
				final message=deep_hash(l);
				return message;

	}
	Map<String,dynamic> toJson(){
		var m=Map<String,dynamic>();
		m["format"]=this.format.toString();
		m["last_tx"]=this.last_tx;
		m["owner"]=this.owner;

		m["tags"]=tags.map((o)=>o.toJson()).toList();
		m["quantity"]=this.quantity;
		m["reward"]=this.reward;
		m["id"]=this.id;
		m["signature"]=this.signature;
		m["target"]=this.target;
		m["data_size"]=this.data_size;
		m["data_root"]=this.data_root;
		m["data"]="";
		return m;
	}
	

  void __set_data(Uint8List data)  {
	  final chunk_marks =   merkle.data_to_chunks(data);
	  final leaves =  		merkle.generate_leaves(chunk_marks);
	  final tree =    		merkle.generate_tree(leaves);
	   this.proofs= 		merkle.generate_proofs(tree);

	  
	  this.proofs=proofs;
	  this.chunk_marks=chunk_marks;
	  this.data_root= binary_to_base64url(tree.id);
	  this.data_size=data.length.toString();
	  this.data=data;
	 
}
	void upload(){
		
	}

	 
}