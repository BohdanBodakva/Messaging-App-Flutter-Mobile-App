import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

class NotificationService {
  final FlutterLocalNotificationsPlugin flutterLocalNotificationsPlugin =
      FlutterLocalNotificationsPlugin();

  Future<void> requestNotificationPermission() async {
    PermissionStatus status = await Permission.notification.request();

    if (status.isGranted) {
      debugPrint("Notification permission granted");
      await initializeNotifications();
    } else {
      debugPrint("Notification permission denied");
    }
  }

  Future<void> initializeNotifications() async {
    const AndroidInitializationSettings androidInitSettings =
        AndroidInitializationSettings('app_logo');

    const InitializationSettings initSettings =
        InitializationSettings(android: androidInitSettings);

    final bool? initialized =
        await flutterLocalNotificationsPlugin.initialize(initSettings);

    if (initialized == null || !initialized) {
      debugPrint("Notification initialization failed!");
    }
  }

  Future<void> showNotification(bool isGroup, String chatName, String userName, String text) async {
    const AndroidNotificationDetails androidDetails = AndroidNotificationDetails(
      'channel_id', 'Channel Name',
      importance: Importance.high,
      priority: Priority.high,
      playSound: true,
    );

    const NotificationDetails details = NotificationDetails(android: androidDetails);

    if (isGroup) {
      await flutterLocalNotificationsPlugin.show(
        0,
        chatName,
        "$userName: $text",
        details,
      );
    } else {
      await flutterLocalNotificationsPlugin.show(
        0,
        userName,
        text,
        details,
      );
    }
    
  }
}
