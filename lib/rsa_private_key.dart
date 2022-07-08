import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';

/// Private keys in RSA
class RSAPrivateKeyX extends RSAAsymmetricKey implements PrivateKey {
  // The secret prime factors of n
  final BigInt p;
  final BigInt q;
  final BigInt e;

  /// Create an RSA private key for the given parameters.
  ///
  /// The optional public exponent parameter has been deprecated. It does not
  /// have to be provided, because it can be calculated from the other values.
  /// The optional parameter is retained for backward compatibility, but it
  /// does not need to be provided.

  RSAPrivateKeyX(
      BigInt modulus,
      BigInt privateExponent,
      this.p,
      this.q,
      this.e)
      : super(modulus, privateExponent) {
    // Check RSA relationship between p, q and modulus hold true.

    if (p * q != modulus) {
      throw ArgumentError.value('modulus inconsistent with RSA p and q');
    }

  }

  /// Get private exponent [d] = e^-1
  @Deprecated('Use privateExponent.')
  BigInt? get d => exponent;

  /// Get the private exponent (d)
  BigInt? get privateExponent => exponent;

  /// Get the public exponent (e)
  BigInt get publicExponent => e;


  @override
  bool operator ==(other) {
    if (other is RSAPrivateKeyX) {
      return other.privateExponent == privateExponent &&
          other.modulus == modulus;
    }
    return false;
  }

  @override
  int get hashCode => modulus.hashCode + privateExponent.hashCode;
}
