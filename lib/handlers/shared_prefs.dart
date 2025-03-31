import 'package:shared_preferences/shared_preferences.dart';

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
