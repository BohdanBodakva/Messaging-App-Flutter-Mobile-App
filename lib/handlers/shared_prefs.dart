import 'package:shared_preferences/shared_preferences.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:pointycastle/export.dart';
import 'package:basic_utils/basic_utils.dart';

Future<void> saveDataToStorage(String key, String value) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString(key, value);
}

Future<String?> getDataFromStorage(String key) async {
  final prefs = await SharedPreferences.getInstance();
  return prefs.getString(key);
}

Future<void> deleteDataFromStorage(String key) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.remove(key);
}

Future<void> saveKeyPair(AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair) async {
  final prefs = await SharedPreferences.getInstance();

  final publicPem = CryptoUtils.encodeRSAPublicKeyToPem(keyPair.publicKey);
  final privatePem = CryptoUtils.encodeRSAPrivateKeyToPem(keyPair.privateKey);

  await prefs.setString('publicKey', publicPem);
  await prefs.setString('privateKey', privatePem);
}

Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>?> loadKeyPair() async {
  final prefs = await SharedPreferences.getInstance();

  final publicPem = prefs.getString('publicKey');
  final privatePem = prefs.getString('privateKey');

  if (publicPem == null || privatePem == null) {
    return null;
  }

  final publicKey = CryptoUtils.rsaPublicKeyFromPem(publicPem);
  final privateKey = CryptoUtils.rsaPrivateKeyFromPem(privatePem);

  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(publicKey, privateKey);
}