import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

class NotificationProvider with ChangeNotifier {
  bool _isNotificationsEnabled = true;
  bool get isNotificationsEnabled => _isNotificationsEnabled;

  NotificationProvider() {
    _loadNotificationStatusFromPrefs();
  }

  Future<void> _loadNotificationStatusFromPrefs() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    bool? savedStatus = prefs.getBool('notifications_enabled');
    _isNotificationsEnabled = savedStatus ?? true;
    notifyListeners();
  }

  Future<void> toggleNotificationStatus() async {
    _isNotificationsEnabled = !_isNotificationsEnabled;

    SharedPreferences prefs = await SharedPreferences.getInstance();
    prefs.setBool('notifications_enabled', _isNotificationsEnabled);

    notifyListeners();
  }

  Future<void> enableNotifications() async {
    _isNotificationsEnabled = true;
    SharedPreferences prefs = await SharedPreferences.getInstance();
    prefs.setBool('notifications_enabled', true);

    notifyListeners();
  }

  Future<void> disableNotifications() async {
    _isNotificationsEnabled = false;
    SharedPreferences prefs = await SharedPreferences.getInstance();
    prefs.setBool('notifications_enabled', false);

    notifyListeners();
  }
}
