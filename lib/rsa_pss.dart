import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/signers/pss_signer.dart';
import 'package:ar_wallet/ar_utils.dart';
import 'dart:math';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:ar_wallet/rsa_private_key.dart';

Future<Uint8List> rsa_pss_sign({required Uint8List message, required RsaKeyPair kp}) async {
  final pk = await kp.extract();

  final pcPk = RSAPrivateKeyX(
    bytes_to_bigint(pk.n),
    bytes_to_bigint(pk.d),
    bytes_to_bigint(pk.p),
    bytes_to_bigint(pk.q),
    bytes_to_bigint(pk.e),
  );

final sr=FortunaRandom()
  ..seed(KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));
  final signer = PSSSignerX(RSAEngine(), SHA256Digest(), SHA256Digest())
    ..init(
      true,
      ParametersWithSaltConfiguration(
        PrivateKeyParameter<RSAPrivateKeyX>(pcPk),
        sr,
        32,
      ),
    );
  return signer.generateSignature(message).bytes;
}

Future<bool> rsa_pss_verify({required Uint8List message,required Uint8List signature,required BigInt e, required BigInt n,}) async {
  final sr=FortunaRandom()
  ..seed(KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));

  var signer = PSSSignerX(RSAEngine(), SHA256Digest(), SHA256Digest())
    ..init(
      false,
      ParametersWithSaltConfiguration(
        PublicKeyParameter<RSAPublicKey>(
          RSAPublicKey(n,e),
        ),
         sr,
        32,
      ),
    );

  return signer.verifySignature(message, PSSSignature(signature));
}




class PSSSignerX implements Signer {


  static const int TRAILER_IMPLICIT = 0xBC;

  final Digest _contentDigest;
  final Digest _mgfDigest;
  final AsymmetricBlockCipher _cipher;
  final int _hLen;
  final int _mgfhLen;
  final int _trailer;

  late bool _sSet;
  late int _sLen;
  late Uint8List _salt;
  late SecureRandom _random;

  late int _emBits;
  late Uint8List _block;
  late Uint8List _mDash;

  late bool _forSigning;

  PSSSignerX(this._cipher, this._contentDigest, this._mgfDigest,
      {int trailer = TRAILER_IMPLICIT})
      : _hLen = _contentDigest.digestSize,
        _mgfhLen = _mgfDigest.digestSize,
        _trailer = trailer;

  @override
  String get algorithmName => '${_mgfDigest.algorithmName}/PSS';

void arrayCopy(Uint8List sourceArr, int sourcePos, Uint8List outArr,int outPos, int len) {
  for (var i = 0; i < len; i++) {
    outArr[outPos + i] = sourceArr[sourcePos + i];
  }
}

  @override
  void init(bool forSigning, CipherParameters params) {
    _forSigning = forSigning;

    AsymmetricKeyParameter akparams;
    if (params is ParametersWithSaltConfiguration) {
      akparams = params.parameters as AsymmetricKeyParameter<AsymmetricKey>;
      _random = params.random;
      _sSet = false;
      _sLen = params.saltLength;
      _salt = Uint8List(_sLen);
    } else if (params is ParametersWithSalt) {
      akparams = params.parameters as AsymmetricKeyParameter<AsymmetricKey>;
      _sSet = true;
      _salt = params.salt;
      _sLen = _salt.length;
    } else {
      throw ArgumentError(
          'Unsupported parameters type ${params.runtimeType}: should be ParametersWithSaltConfiguration or ParametersWithSalt');
    }

    var k = akparams.key as RSAAsymmetricKey;

    if (forSigning && (k is! RSAPrivateKeyX)) {
      throw ArgumentError('Signing requires private key');
    }

    if (!forSigning && (k is! RSAPublicKey)) {
      throw ArgumentError('Verification requires public key');
    }

   /* if (!forSigning && !_sSet) {
      throw ArgumentError('Verification requires salt');
    }
*/
    _emBits = k.modulus!.bitLength - 1;

    if (_emBits < (8 * _hLen + 8 * _sLen + 9)) {
      throw ArgumentError('Key too small for specified hash and salt lengths');
    }

    _mDash = Uint8List(8 + _sLen + _contentDigest.digestSize);

    _cipher.init(forSigning, akparams);

    _block = Uint8List((_emBits + 7) ~/ 8);

    reset();
  }

  /// Clear possibly sensitive data.
  void _clearBlock(Uint8List block) {
    for (var i = 0; i != block.length; i++) {
      block[i] = 0;
    }
  }

  @override
  void reset() {
    _contentDigest.reset();
  }

  @override
  PSSSignature generateSignature(Uint8List message) {
    if (!_forSigning) {
      throw StateError('Signer was not initialised for signature generation');
    }

    _contentDigest.reset();
    _contentDigest.update(message, 0, message.length);
    _contentDigest.doFinal(_mDash, _mDash.length - _hLen - _sLen);

    if (_sLen != 0) {
      if (!_sSet) {
        _salt = _random.nextBytes(_sLen);
      }

      arrayCopy(_salt, 0, _mDash, _mDash.length - _sLen, _sLen);
    }

    var h = Uint8List(_hLen);

    _contentDigest.update(_mDash, 0, _mDash.length);

    _contentDigest.doFinal(h, 0);

    _block[_block.length - _sLen - 1 - _hLen - 1] = 0x01;
    arrayCopy(_salt, 0, _block, _block.length - _sLen - _hLen - 1, _sLen);

    var dbMask =
        _maskGeneratorFunction1(h, 0, h.length, _block.length - _hLen - 1);
    for (var i = 0; i != dbMask.length; i++) {
      _block[i] ^= dbMask[i];
    }

    arrayCopy(h, 0, _block, _block.length - _hLen - 1, _hLen);

    var firstByteMask = 0xff >> ((_block.length * 8) - _emBits);

    _block[0] &= firstByteMask;
    _block[_block.length - 1] = _trailer;

    var b = _cipher.process(_block);

    _clearBlock(_block);

    return PSSSignature(b);
  }

  @override
  bool verifySignature(Uint8List message, covariant PSSSignature signature) {
    if (_forSigning) {
      throw StateError('Signer was not initialised for signature verification');
    }

    _contentDigest.reset();
    _contentDigest.update(message, 0, message.length);
    _contentDigest.doFinal(_mDash, _mDash.length - _hLen - _sLen);

    var b = _cipher.process(signature.bytes);
    _block.fillRange(0, _block.length - b.length, 0);
    arrayCopy(b, 0, _block, _block.length - b.length, b.length);

    var firstByteMask = 0xFF >> ((_block.length * 8) - _emBits);

    if (_block[0] != (_block[0] & firstByteMask) ||
        _block[_block.length - 1] != _trailer) {
      _clearBlock(_block);
      return false;
    }

    var dbMask = _maskGeneratorFunction1(
        _block, _block.length - _hLen - 1, _hLen, _block.length - _hLen - 1);

    for (var i = 0; i != dbMask.length; i++) {
      _block[i] ^= dbMask[i];
    }

    _block[0] &= firstByteMask;

    for (var i = 0; i != _block.length - _hLen - _sLen - 2; i++) {
      if (_block[i] != 0) {
        _clearBlock(_block);
        return false;
      }
    }

    if (_block[_block.length - _hLen - _sLen - 2] != 0x01) {
      _clearBlock(_block);
      return false;
    }

    if (_sSet) {
      arrayCopy(_salt, 0, _mDash, _mDash.length - _sLen, _sLen);
    } else {
      arrayCopy(_block, _block.length - _sLen - _hLen - 1, _mDash,
          _mDash.length - _sLen, _sLen);
    }

    _contentDigest.update(_mDash, 0, _mDash.length);
    _contentDigest.doFinal(_mDash, _mDash.length - _hLen);

    for (var i = _block.length - _hLen - 1, j = _mDash.length - _hLen;
        j != _mDash.length;
        i++, j++) {
      if ((_block[i] ^ _mDash[j]) != 0) {
        _clearBlock(_mDash);
        _clearBlock(_block);
        return false;
      }
    }

    _clearBlock(_mDash);
    _clearBlock(_block);
    return true;
  }

  /// Convert int to octet string.
  void _intToOSP(int i, Uint8List sp) {
    sp[0] = i >> 24;
    sp[1] = i >> 16;
    sp[2] = i >> 8;
    sp[3] = i >> 0;
  }

  Uint8List _maskGeneratorFunction1(
      Uint8List Z, int zOff, int zLen, int length) {
    var mask = Uint8List(length);
    var hashBuf = Uint8List(_mgfhLen);
    var C = Uint8List(4);
    var counter = 0;

    _mgfDigest.reset();

    while (counter < (length ~/ _mgfhLen)) {
      _intToOSP(counter, C);

      _mgfDigest.update(Z, zOff, zLen);
      _mgfDigest.update(C, 0, C.length);
      _mgfDigest.doFinal(hashBuf, 0);

      arrayCopy(hashBuf, 0, mask, counter * _mgfhLen, _mgfhLen);
      counter++;
    }

    if ((counter * _mgfhLen) < length) {
      _intToOSP(counter, C);

      _mgfDigest.update(Z, zOff, zLen);
      _mgfDigest.update(C, 0, C.length);
      _mgfDigest.doFinal(hashBuf, 0);

      arrayCopy(hashBuf, 0, mask, counter * _mgfhLen,
          mask.length - (counter * _mgfhLen));
    }

    return mask;
  }
}
