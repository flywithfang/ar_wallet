import 'dart:io';
import 'package:ar_wallet/ar_wallet.dart';
import 'package:ar_wallet/ar_type.dart';

Map<String,Account> load_address(String path){
 var wallet_addrs= Map<String,Account>();
	var dir = Directory(path);
	for(var e in dir.listSync()){
		final path = e.path;
		//print(path);
		if(-1==path.indexOf("arweave-keyfile-"))
			continue;
		File f = File(path);
		final s=f.readAsStringSync();
		final acc=WalletApi.parse_jwk(s);
		final addr= acc.get_address();
	
		wallet_addrs[addr]=acc;

	}

	return wallet_addrs;

}