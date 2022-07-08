import 'package:jwk/jwk.dart';

import 'package:cryptography/cryptography.dart';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:ar_wallet/ar_tx.dart';
import 'package:ar_wallet/ar_type.dart';
import 'package:ar_wallet/ar_utils.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';

class GetPriceRet{
  String? error;
  double last=0;
  double volume=0;
}
class GetBalanceResult{
  BigInt total=BigInt.zero;
  Map<String,BigInt> addrs=Map<String,BigInt>();
}
class SendArResult{
  ARTx? tx;
  String? error;
  SendArResult(this.tx,this.error);
}
class SendDataResult{
  ARTx? tx;
  String? error;
  SendDataResult(this.tx,this.error);
}
class GetTxStatusRet{
  String? error;
  int? confirmations;
}
class ReadDataRet{
  String? error;
  Uint8List? data;
}
class WalletApi{
   static String ar_endpoint="http://ar-pool.2life.online:1984/";//"https://arweave.net/";//

  static Account parse_jwk(String v){
   
     // print(v);

      var w = jsonDecode(v);
      assert(w is Map);
      //print('n:${w["n"]}\nd:${w["d"]}');

      List<int> n = decode_base64_binary(w["n"]);
      List<int> e = decode_base64_binary(w["e"]);
      List<int> p = decode_base64_binary(w["p"]);
      List<int> q = decode_base64_binary(w["q"]);
      List<int> d = decode_base64_binary(w["d"]);

      var kp=RsaKeyPairData(n:n,e:e,p:p,q:q,d:d);
      return Account(kp:kp);

  }
  static void set_endpoint(String url){
    ar_endpoint=url;
  }

  static Future<GetBalanceResult> get_balances(Iterable<String> addrs)async {
    var r = GetBalanceResult();
    for(var addr in addrs){
      final balance = await get_balance(addr);
      r.total+=balance;
      r.addrs[addr]=balance;
    }
    return r;
  }
  static Future<BigInt> get_balance(String addr)async{

    var url = Uri.parse("${ar_endpoint}wallet/${addr}/balance/");
    var response = await http.get(url);
 //   print('Response status: ${response.statusCode}');
   // print('Response body: ${response.body}');
    if(response.statusCode!=200){
      throw "invalid balance";
    }else{
          return BigInt.parse(response.body);
    }
  }

    static Future<int> get_transfer_fee(String addr)async{

    var url = Uri.parse("${ar_endpoint}price/0/${addr}");
    var response = await http.get(url);
 //   print('Response status: ${response.statusCode}');
   // print('Response body: ${response.body}');
    if(response.statusCode!=200){
      throw "invalid price";
    }else{
          return int.parse(response.body);
    }
  }

   static Future<GetTxStatusRet> get_tx_status(String tx_id)async{

    var url = Uri.parse("${ar_endpoint}tx/${tx_id}/status");
    var response = await http.get(url);


   var r=GetTxStatusRet();
   if(response.statusCode>=200 && response.statusCode<300){
      if(response.body=="Pending"){
        r.confirmations=0;
      }else{
            var w = jsonDecode(response.body);
            assert(w is Map);

            var h = w["block_height"];
            var bh= w["block_indep_hash"];
            int n_confirm=w["number_of_confirmations"];
            r.confirmations=n_confirm;
          }
    }
    else{
       r.error =response.body;
    }
    return r;
  }

    static Future<String> get_tx_anchor()async{

    var url = Uri.parse("${ar_endpoint}tx_anchor/");
    var response = await http.get(url);
   // print('Response status: ${response.statusCode}');
   // print('Response body: ${response.body}');
    if(response.statusCode!=200){
       throw "invalid tx_anchor";
    }else{
          return response.body;
    }
  }
  static Future<SendArResult> send_ar(Account acc ,String dst,int amount)async{
    var tx_anchor = await get_tx_anchor();
    print(tx_anchor);
    var fee=await get_transfer_fee(dst);
    print(fee);
    var tx=ARTx();
    await tx.init_transfer(acc,dst,amount,tx_anchor,fee);

    await tx.sign(acc);

      final error= await post_tx(tx);
   
      return SendArResult(tx,error);

  }
static Future<Account> new_account() async {
    final secureRandom = FortunaRandom();
    final seedSource = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final keyGen = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(
            AR_publicExponent,
            AR_keyLength,
            64,
          ),
          secureRandom,
        ),
      );

    final pair = keyGen.generateKeyPair();

    final privK = pair.privateKey as RSAPrivateKey;

    return Account(
      kp: RsaKeyPairData(
        e: encodeBigIntToBytes(privK.publicExponent!),
        n: encodeBigIntToBytes(privK.modulus!),
        d: encodeBigIntToBytes(privK.privateExponent!),
        p: encodeBigIntToBytes(privK.p!),
        q: encodeBigIntToBytes(privK.q!),
      ),
    );
  }

static Future<String?> post_chunk({required Uint8List chunk,required Uint8List chunk_path,required int data_size, required Uint8List data_root,required int chunk_offset})async{

      var j =<String,dynamic> {
        "chunk":binary_to_base64url(chunk),
        "data_path":binary_to_base64url(chunk_path),
        "data_size":data_size.toString(),
        "data_root":binary_to_base64url(data_root),
        "offset":chunk_offset.toString()};

    var url = Uri.parse("${ar_endpoint}chunk/");
    final js=json.encode(j);
    print(js);
    var response = await http.post(url, body:js);
   // print('Response status: ${response.statusCode}');
   // print('Response body: ${response.body}');
    if(response.statusCode!=200){
      return  response.body;
    }else{
          return null;
    }
  }

 static Future<String?> get_tx(Account acc)async{

     var url = Uri.parse("${ar_endpoint}tx");

    var response = await http.get(url);
    print('Response status: ${response.statusCode}');
    print('Response body: ${response.body}');
    print('headers: ${response.headers}');
   
    if(response.statusCode!=200){
        return response.body;
    }else{
       return null;
    }

 }
  static Future<String?> post_tx(ARTx tx)async{

     var url = Uri.parse("${ar_endpoint}tx");

      final tx_str=jsonEncode(tx);
    var response = await http.post(url,body:tx_str);
    print('Response status: ${response.statusCode}');
    print('Response body: ${response.body}');
    print('headers: ${response.headers}');
   
    if(response.statusCode!=200){
        return response.body;
    }else{
       return null;
    }

 }
 static Future<ReadDataRet> read_data(Account acc,String tx_id )async{

     var url = Uri.parse("${ar_endpoint}tx/${tx_id}/data");

    var response = await http.get(url);
    print('Response status: ${response.statusCode}');
    print('Response body: ${response.body}');
    print('headers: ${response.headers}');
   
   var r=ReadDataRet();
    if(response.statusCode!=200){
       r.error=response.body;
    }else{
    }
    return r;

 }
 static Future<GetPriceRet>  get_price(String pair)async{
   final url = Uri.parse('https://api.gateio.ws/api/v4/spot/tickers?currency_pair=${pair}');
   var response = await http.get(url);
    var r=GetPriceRet();
    if(response.statusCode!=200){
       r.error=response.body;
    }else{
    //  print(response.body);
      Map<String,dynamic> j = json.decode(response.body)[0];
      r.last=double.parse(j["last"]);
      r.volume=double.parse(j["base_volume"]);
    }
    return r;
 }

}