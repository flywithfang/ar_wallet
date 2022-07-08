import 'package:cryptography/cryptography.dart';
import 'dart:convert';
import 'package:ar_wallet/ar_utils.dart';
import 'package:crypto/crypto.dart';

class Account{
  RsaKeyPairData kp;
  Account({required this.kp});

  String get_pub_key_base64url(){
    return binary_to_base64url(this.kp.n);
  }
  String get_address(){
    return binary_to_base64url(sha256.convert(this.kp.n).bytes);
  }
  void verify(){
    final p=bytes_to_bigint(kp.p);
    final q=bytes_to_bigint(kp.q);
    final d=bytes_to_bigint(kp.d);
    final e2=bytes_to_bigint(kp.e);
    final m=(p - BigInt.one) * (q - BigInt.one);
    final gcd=(p - BigInt.one).gcd(q-BigInt.one);
    final lcm=m~/gcd;
    final e3=d.modInverse(lcm);
    final e = d.modInverse(m);
     print("p:${bigint_to_base64url(p)}\nq:${bigint_to_base64url(q)}\n d:${bigint_to_base64url(d)}\ne:$e,\ne2:${e2}\n e3:${e3}");


  }
}