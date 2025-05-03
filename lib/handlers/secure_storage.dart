import 'package:flutter_secure_storage/flutter_secure_storage.dart';

final secureStorage = FlutterSecureStorage();

Future<void> saveKeyPair(String privatePem, String publicPem) async {
  await secureStorage.write(key: 'rsa_private_key', value: privatePem);
  await secureStorage.write(key: 'rsa_public_key', value: publicPem);
}

Future<String?> getPrivateKey() async {
  return await secureStorage.read(key: 'rsa_private_key');
}

Future<String?> getPublicKey() async {
  return await secureStorage.read(key: 'rsa_public_key');
}
