import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

class LanguageProvider with ChangeNotifier {
  Locale _locale = const Locale('en', 'US');
  Map<String, String> _localizedStrings = {};

  Locale get locale => _locale;
  Map<String, String> get localizedStrings => _localizedStrings;

  LanguageProvider() {
    _loadLanguageFromPrefs();
  }

  Future<void> loadLanguage(String languageCode) async {
    String jsonString = await rootBundle.loadString('assets/lang/$languageCode.json');
    Map<String, dynamic> jsonMap = json.decode(jsonString);
    _localizedStrings = jsonMap.map((key, value) => MapEntry(key, value.toString()));

    _locale = Locale(languageCode);
    SharedPreferences prefs = await SharedPreferences.getInstance();
    prefs.setString('language_code', languageCode);

    notifyListeners();
  }

  Future<void> _loadLanguageFromPrefs() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    String? languageCode = prefs.getString('language_code') ?? 'en';
    await loadLanguage(languageCode);
  }

  void setLocale(String languageCode) {
    loadLanguage(languageCode);
  }
}
