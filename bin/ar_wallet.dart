import 'package:ar_wallet/ar_wallet.dart';
import 'package:ar_wallet/ar_tx.dart';
import 'package:ar_wallet/ar_utils.dart';
import 'package:ar_wallet/address.dart' as ads;
import 'dart:convert';
import 'dart:typed_data';
import 'package:args/args.dart';
import 'package:ar_wallet/ar_deep_hash.dart';
import "package:ar_wallet/merkle_chunk.dart" as merkle;
import "package:crypto/crypto.dart";

/*
balance
send xxx yyyy 2000000 -
upload

* */

void main(List<String> arguments)async {

  var parser = ArgParser();
  parser.addOption("dir",abbr:"w",mandatory:true,help:"wallet directory -w");
  parser.addOption("host",abbr:"h",mandatory:false,help:"remote endpoint");
  parser.addCommand("balance");
  parser.addCommand("send");
  parser.addCommand("upload");
  parser.addCommand("tx");
  parser.addCommand("merkle_test");

 //9,223,372,036,854,775,807

  var R=parser.parse(arguments);


  if(R.command==null)
    return;
  final wallet_dir=R["dir"];
  var wallet_addrs=  ads.load_address(wallet_dir);
  final addrs=wallet_addrs.keys;
  //print(addrs);

  if(R["host"]!=null){
    WalletApi.set_endpoint(R["host"]);
  }
  final cmd=R.command!;
  if(cmd.name=="balance"){
    final r=await WalletApi.get_price("AR_USDT");
    if(r.error!=null){
      print(r.error); return;
    }
    final price=r.last;
    final volume=r.volume;
     var w = await WalletApi.get_balances(addrs);
      print(winston_to_ar(w.total)+"AR");
      final total_usdt=w.total/BigInt.from(1000000000000)*price;
      print("usd:${total_usdt.toStringAsFixed(0)}\$");

      print("pri:${price.toStringAsFixed(2)}\$");
      print("vol:${volume.toStringAsFixed(0)}\$");


    for(var addr in w.addrs.keys){
      final balance=w.addrs[addr]!;
      print("$addr ${winston_to_ar(balance)}AR");
    }

  }else if(cmd.name=="send"){
     print(cmd.rest);
     if(cmd.rest.length<3){
      print("send src dst ar");
      return;
     }
     final src_addr=cmd.rest[0];
     final dst_addr=cmd.rest[1];
     final amount = int.parse(cmd.rest[2]);
    
     var acc = wallet_addrs[src_addr]!;
   
     final send_r=await WalletApi.send_ar(acc,dst_addr,amount);
     if(send_r.error !=null){
        print(send_r.error);
     }else{
        print(jsonEncode(send_r.tx!));
        print(send_r.tx!.id);
     }
  }else if(cmd.name=="tx"){
      if(cmd.rest.length<1){
         print("tx id");
         return;
       }
       final tx_id=cmd.rest[0];
       final r=await WalletApi.get_tx_status(tx_id);
       if(r.error!=null){
          print(r.error!);
       }else{
          print("confirmations:${r.confirmations!}");
       }
     
  }else if(cmd.name=="merkle_test"){
      final str="abcdefghij";
      final bin=utf8.encoder.convert(str);
      if(bin.length!=str.length) throw "bad string";


      var chunk_marks=<merkle.ChunkMark>[];
      int end=0;
      for(int c in bin){
        chunk_marks.add(merkle.ChunkMark(Uint8List.fromList(sha256.convert(bin.sublist(end,end+1)).bytes),++end));
      }
      for(var e in chunk_marks){
        print(json.encode(e));
      }
      final leaves=merkle.generate_leaves(chunk_marks);
      final tree=merkle.generate_tree(leaves);
      print("tree id:${tree.id}");
      final proofs=merkle.generate_proofs(tree);
      final proof=proofs[5];

      print("offset:${proof.offset},path:${proof.chunk_path}");

      final b1=merkle.validate_path(tree.id,proof.offset,proof.chunk_path);
      final b2=merkle.validate_path(tree.id,0,proof.chunk_path);
      print("valid path (${b1.valid},${b1.end}),(${b2.valid},${b2.end})");
      

    }else{
    print("unknown cmd ${cmd.name}");
  }
}
