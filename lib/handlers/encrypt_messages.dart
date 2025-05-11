import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:messaging_app/handlers/http_request.dart';
import 'package:messaging_app/handlers/shared_prefs.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:asn1lib/asn1lib.dart';
import 'dart:math' as math;
import 'package:socket_io_client/socket_io_client.dart';


// var keyPair;
// var serverPublicKey;

Future<void> generateKeyPair(Socket socket) async {  
  final keyPair1 = await _generateRSAkeyPair(2048);

  await saveKeyPair(keyPair1);
  // keyPair = keyPair1;
  
  await _exchangePublicKeys(socket);

  // print("Client key pair generated: ${keyPair != null}");
  // print("Server public key received: ${serverPublicKey != null}");
}

Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> _generateRSAkeyPair(int bitLength) async {
  // Create a secure random number generator
  final secureRandom = FortunaRandom();
  final seedSource = math.Random.secure();
  final seeds = <int>[];
  for (int i = 0; i < 32; i++) {
    seeds.add(seedSource.nextInt(255));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
  
  // Create an RSA key generator and generate key pair
  final keyGen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(65537), bitLength, 64),
        secureRandom));

  // Generate the key pair
  final keyPair = keyGen.generateKeyPair();
  
  // Extract the keys and explicitly cast them to the appropriate types
  final publicKey = keyPair.publicKey as RSAPublicKey;
  final privateKey = keyPair.privateKey as RSAPrivateKey;
  
  // Create a new AsymmetricKeyPair with the properly typed keys
  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
    publicKey, privateKey
  );
}

Future<void> _exchangePublicKeys(Socket socket) async {
  final keyPair = await loadKeyPair();

  if (keyPair == null) return;
  
  try {    
    // Convert public key to PEM format
    final publicKeyPem = _encodePublicKeyToPem(keyPair!.publicKey);

    // Set up listener for server response before emitting
    socket.once("exchange_keys_response", (data) async {
      print("Received key exchange response from server");
      
      if (data['server_public_key'] != null) {
        final serverPublicKey = data['server_public_key'];
        // print("Server public key received (first 50 chars): ${serverPublicKey!.substring(0, math.min(50, serverPublicKey!.length))}");
        
        

        // Immediately test if we can parse it
        final parsedKey = _parseServerPublicKey(serverPublicKey!);
        if (parsedKey != null) {
          print("Successfully parsed server public key");

          await saveDataToStorage("serverPublicKey", serverPublicKey);

          print("SAVED KEY____________: ${getDataFromStorage("serverPublicKey")}");
        } else {
          print("Failed to parse server public key");
        }
      } else {
        print("Server did not send public key");
      }
    });

    // Send public key to server
    socket.emit("exchange_keys", {
      "client_public_key": publicKeyPem
    });
    
    print("Sent public key to server");
  } catch (e) {
    print("Error in key exchange: $e");
  }
}

String _encodePublicKeyToPem(RSAPublicKey publicKey) {
  // Create ASN1 sequence for public key
  var algorithmSeq = ASN1Sequence();
  var algorithm = ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]);
  var paramsAsn1 = ASN1Null();
  algorithmSeq.add(algorithm);
  algorithmSeq.add(paramsAsn1);

  var publicKeySeq = ASN1Sequence();
  publicKeySeq.add(ASN1Integer(publicKey.modulus!));
  publicKeySeq.add(ASN1Integer(publicKey.exponent!));
  var publicKeySeqBitString = ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

  var topLevelSeq = ASN1Sequence();
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqBitString);

  var dataBase64 = base64.encode(topLevelSeq.encodedBytes);
  return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
}

RSAPublicKey? _parseServerPublicKey(String pemString) {
  try {
    // First, determine which format we're dealing with
    bool isPKCS1Format = pemString.contains('-----BEGIN RSA PUBLIC KEY-----');
    
    // Clean up the PEM string
    final pemContents = pemString
        .replaceAll('-----BEGIN RSA PUBLIC KEY-----', '')
        .replaceAll('-----END RSA PUBLIC KEY-----', '')
        .replaceAll('-----BEGIN PUBLIC KEY-----', '')
        .replaceAll('-----END PUBLIC KEY-----', '')
        .replaceAll('\r', '')
        .replaceAll('\n', '')
        .trim();
    
    // Decode the base64 data
    final decodedData = base64.decode(pemContents);
    final asn1Parser = ASN1Parser(decodedData);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    
    if (isPKCS1Format) {
      // PKCS#1 format (direct sequence of modulus and exponent)
      // In PKCS#1, the sequence directly contains modulus and exponent
      print("Parsing PKCS#1 format");
      
      // Extract modulus and exponent directly from the sequence
      final modulus = (topLevelSeq.elements[0] as ASN1Integer).valueAsBigInteger;
      final exponent = (topLevelSeq.elements[1] as ASN1Integer).valueAsBigInteger;
      
      return RSAPublicKey(modulus!, exponent!);
    } else {
      // X.509 SubjectPublicKeyInfo format
      print("Parsing X.509 format");
      
      // In X.509, there's an algorithm identifier followed by a bit string containing the key
      if (topLevelSeq.elements.length < 2) {
        throw FormatException("Invalid X.509 structure: not enough elements in sequence");
      }
      
      // The second element should be a bit string containing the key data
      final publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;
      
      // Parse the bit string content as another ASN.1 structure
      final publicKeyAsn = ASN1Parser(publicKeyBitString.stringValue as Uint8List);
      final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
      
      // Extract modulus and exponent
      final modulus = (publicKeySeq.elements[0] as ASN1Integer).valueAsBigInteger;
      final exponent = (publicKeySeq.elements[1] as ASN1Integer).valueAsBigInteger;
      
      return RSAPublicKey(modulus!, exponent!);
    }
  } catch (e) {
    print('Error parsing public key: $e');
    // Print more detailed information for debugging
    print('PEM string format: ${pemString.substring(0, math.min(50, pemString.length))}...');
    return null;
  }
}

Future<String?> encryptText(String text) async {
  final serverPublicKey = await getDataFromStorage("serverPublicKey");

  if (serverPublicKey == null) {
    print("Server public key is null. Cannot encrypt message.");
    return null;
  }
  
  try {
    print("Encrypting message with server public key");
    final serverPublicKey1 = _parseServerPublicKey(serverPublicKey!);
    
    if (serverPublicKey1 == null) {
      print("Failed to parse server public key for encryption");
      return null;
    }
    
    // The Python 'rsa' library expects PKCS#1 padding, so make sure we're using compatible encryption
    // For pointycastle, we need to manually apply PKCS#1 v1.5 padding
    final encryptedMessage = _encryptWithPublicKeyPKCS1(text, serverPublicKey1);
    
    return base64.encode(encryptedMessage);
  } catch (e) {
    print("Error during encryption: $e");
    return null;
  }
}

Future<String?> decryptText(Uint8List encryptedData) async {
  final keyPair = await loadKeyPair();

  if (keyPair == null || keyPair!.privateKey == null) {
    print("Private key is null. Cannot decrypt message.");
    return null;
  }
  
  try {
    // Print the first few bytes for debugging
    print("Encrypted data first bytes: ${encryptedData.length > 4 ? '0x${encryptedData[0].toRadixString(16).padLeft(2, '0')} 0x${encryptedData[1].toRadixString(16).padLeft(2, '0')} 0x${encryptedData[2].toRadixString(16).padLeft(2, '0')} 0x${encryptedData[3].toRadixString(16).padLeft(2, '0')}' : 'too short to display'}");
    
    // Determine the block size based on the key size
    final keySize = (keyPair!.privateKey.modulus!.bitLength + 7) ~/ 8;
    print("RSA key size: $keySize bytes");
    print("Encrypted data size: ${encryptedData.length} bytes");
    
    // Check if the encrypted data needs to be decoded from base64
    // First, see if it's already in the correct format
    if (encryptedData.length == keySize) {
      print("Data length matches key size, attempting direct decryption");
      try {
        return _decryptWithPrivateKey(encryptedData, keyPair!.privateKey);
      } catch (e) {
        print("Direct decryption failed: $e");
        // Continue to other approaches
      }
    }
    
    // Try to decode as base64 if the length is not what we expect
    if (encryptedData.length != keySize) {
      print("Attempting to parse as base64...");
      
      try {
        // Try to decode from base64 if that's how it was transmitted
        final base64String = utf8.decode(encryptedData);
        final decodedData = base64.decode(base64String);
        print("Decoded from base64, new length: ${decodedData.length} bytes");
        
        // Try decrypting the decoded data
        if (decodedData.length == keySize) {
          return _decryptWithPrivateKey(decodedData, keyPair!.privateKey);
        } else if (decodedData.length > keySize) {
          // If the data is still too large, we need to process it in chunks
          return _decryptLargeMessage(decodedData, keyPair!.privateKey);
        } else {
          throw Exception("Decoded data length (${decodedData.length}) is less than key size ($keySize)");
        }
      } catch (e) {
        print("Base64 approach failed: $e");
        
        // Last resort - try to handle as raw binary data
        print("Trying to handle as raw binary data");
        if (encryptedData.length > keySize) {
          // If the data is not base64-encoded, it might be directly chunked binary data
          if (encryptedData.length % keySize != 0) {
            print("Warning: Encrypted data length (${encryptedData.length}) is not a multiple of key size ($keySize)");
            // Try anyway with potentially incomplete last block
          }
          return _decryptLargeMessage(encryptedData, keyPair!.privateKey);
        } else {
          // The data is smaller than key size - pad it?
          print("Data is smaller than key size, attempting to pad");
          final paddedData = Uint8List(keySize);
          for (int i = 0; i < encryptedData.length; i++) {
            paddedData[keySize - encryptedData.length + i] = encryptedData[i];
          }
          return _decryptWithPrivateKey(paddedData, keyPair!.privateKey);
        }
      }
    }
    
    // If we get here, try one last direct approach
    return _decryptWithPrivateKey(encryptedData, keyPair!.privateKey);
  } catch (e) {
    print("Error during decryption: $e");
    return null;
  }
}

String _decryptLargeMessage(Uint8List encryptedData, RSAPrivateKey privateKey) {
  final keySize = (privateKey.modulus!.bitLength + 7) ~/ 8;
  final numBlocks = (encryptedData.length + keySize - 1) ~/ keySize;
  final decryptedParts = <String>[];
  
  print("Decrypting large message in $numBlocks blocks");
  
  for (int i = 0; i < numBlocks; i++) {
    final startPos = i * keySize;
    final endPos = math.min(startPos + keySize, encryptedData.length);
    final blockSize = endPos - startPos;
    
    if (blockSize == keySize) {  // Only process full blocks
      final block = Uint8List(blockSize);
      for (int j = 0; j < blockSize; j++) {
        block[j] = encryptedData[startPos + j];
      }
      
      try {
        final decryptedBlock = _decryptWithPrivateKey(block, privateKey);
        if (decryptedBlock != null) {
          decryptedParts.add(decryptedBlock);
        } else {
          print("Failed to decrypt block $i");
        }
      } catch (e) {
        print("Error decrypting block $i: $e");
      }
    } else {
      print("Skipping partial block of size $blockSize");
    }
  }
  
  return decryptedParts.join();
}

Uint8List _encryptWithPublicKeyPKCS1(String plainText, RSAPublicKey publicKey) {
  // Convert message to UTF-8 bytes
  final messageBytes = utf8.encode(plainText);
  
  // Calculate the maximum message size
  // For PKCS#1 v1.5, the maximum is keySize - 11 bytes
  final keySize = (publicKey.modulus!.bitLength + 7) ~/ 8;
  final maxMessageLength = keySize - 11;
  
  if (messageBytes.length > maxMessageLength) {
    throw Exception("Message too long for RSA encryption with PKCS#1 padding. " +
                   "Maximum length: $maxMessageLength bytes, got: ${messageBytes.length} bytes");
  }
  
  // Set up RSA engine
  final cipher = RSAEngine()
    ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
  
  // Apply PKCS#1 v1.5 padding manually (this is a simplified version)
  final padded = _applyPKCS1Padding(Uint8List.fromList(messageBytes), keySize);
  
  // Encrypt the message
  return cipher.process(padded);
}

Uint8List _applyPKCS1Padding(Uint8List data, int blockSize) {
  // Implementation of PKCS#1 v1.5 padding
  // Format: 00 || 02 || PS || 00 || M
  // where PS is random non-zero bytes
  
  final random = math.Random.secure();
  final padLength = blockSize - data.length - 3;
  
  if (padLength < 8) {
    throw Exception("Data too long for RSA block size");
  }
  
  final padded = Uint8List(blockSize);
  
  // Start with 0x00 0x02 for PKCS#1 v1.5
  padded[0] = 0x00;
  padded[1] = 0x02;
  
  // Fill with random non-zero bytes
  for (int i = 2; i < padLength + 2; i++) {
    int r;
    do {
      r = random.nextInt(256);
    } while (r == 0);
    padded[i] = r;
  }
  
  // Add 0x00 separator
  padded[padLength + 2] = 0x00;
  
  // Copy the data
  for (int i = 0; i < data.length; i++) {
    padded[padLength + 3 + i] = data[i];
  }
  
  return padded;
}

String _decryptWithPrivateKey(Uint8List cipherText, RSAPrivateKey privateKey) {
  try {
    // Print first few bytes for debugging
    print("Decrypting block of size ${cipherText.length} bytes");
    
    final cipher = RSAEngine()
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    
    final decryptedBytes = cipher.process(cipherText);
    print("Raw decrypted size: ${decryptedBytes.length} bytes");
    
    // Remove PKCS#1 v1.5 padding
    final unpaddedBytes = _removePKCS1Padding(decryptedBytes);
    
    // Try to interpret as UTF-8
    try {
      final text = utf8.decode(unpaddedBytes);
      print("Successfully decoded as UTF-8, length: ${text.length} chars");
      return text;
    } catch (e) {
      print("UTF-8 decode failed: $e");
      
      // If UTF-8 fails, try checking if the data is a JSON or has another format
      // For now, just return as hex string for debugging
      return "HEX:" + unpaddedBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
    }
  } catch (e) {
    print("Decryption process failed: $e");
    throw e;
  }
}

Uint8List _removePKCS1Padding(Uint8List paddedData) {
  print("Decrypted data first bytes: 0x${paddedData[0].toRadixString(16).padLeft(2, '0')} 0x${paddedData[1].toRadixString(16).padLeft(2, '0')}");
  
  // Check for proper PKCS#1 v1.5 padding format (0x00, 0x02)  
  if (paddedData[0] != 0x00 || paddedData[1] != 0x02) {
    print("Warning: Non-standard PKCS#1 padding detected");
    
    // Try to handle alternative padding formats
    // Some implementations might use different padding schemes
    
    // Option 1: Try to find 0x00 byte and assume data starts after it
    int separatorIndex = 0;
    while (separatorIndex < paddedData.length && paddedData[separatorIndex] != 0x00) {
      separatorIndex++;
    }
    
    if (separatorIndex < paddedData.length - 1) {
      // Found a 0x00 byte, assume data starts after it
      print("Found 0x00 byte at position $separatorIndex, extracting data");
      final messageLength = paddedData.length - separatorIndex - 1;
      final messageBytes = Uint8List(messageLength);
      
      for (int i = 0; i < messageLength; i++) {
        messageBytes[i] = paddedData[separatorIndex + 1 + i];
      }
      
      // Verify if result looks like UTF-8 text
      try {
        final text = utf8.decode(messageBytes);
        if (text.isNotEmpty) {
          print("Successfully extracted data after 0x00 byte");
          return messageBytes;
        }
      } catch (e) {
        print("Extracted data is not valid UTF-8");
      }
    }
    
    // Option 2: Try to interpret the entire payload as the message
    try {
      final text = utf8.decode(paddedData);
      if (text.isNotEmpty) {
        print("Successfully interpreted entire payload as UTF-8");
        return paddedData;
      }
    } catch (e) {
      print("Entire payload is not valid UTF-8");
    }
    
    // Option 3: Look for common message patterns or headers
    // This would depend on your application's specific message format
    
    throw Exception("Invalid PKCS#1 padding prefix: Unable to extract valid data");
  }
  
  // Standard PKCS#1 v1.5 padding - find the 0x00 separator
  int separatorIndex = 2;
  while (separatorIndex < paddedData.length && paddedData[separatorIndex] != 0x00) {
    separatorIndex++;
  }
  
  if (separatorIndex == paddedData.length) {
    throw Exception("Invalid PKCS#1 padding format: Missing 0x00 separator");
  }
  
  // Extract the original data (after the 0x00 separator)
  final messageLength = paddedData.length - separatorIndex - 1;
  final messageBytes = Uint8List(messageLength);
  
  for (int i = 0; i < messageLength; i++) {
    messageBytes[i] = paddedData[separatorIndex + 1 + i];
  }
  
  return messageBytes;
}