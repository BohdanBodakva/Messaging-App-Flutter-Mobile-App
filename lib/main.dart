import 'package:flutter/material.dart';
import 'dart:async';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:messaging_app/pages/login.dart';
import 'package:messaging_app/providers/language_provider.dart';
import 'package:messaging_app/providers/notification_provider.dart';
import 'package:provider/provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return 
    //ChangeNotifierProvider<LanguageProvider>(
      //create: (_) => LanguageProvider(),
    MultiProvider(
      providers: [
        ChangeNotifierProvider<LanguageProvider>(create: (_) => LanguageProvider()),
        ChangeNotifierProvider<NotificationProvider>(create: (_) => NotificationProvider()),
      ],
      child: Consumer<LanguageProvider>(
        builder: (context, languageProvider, _) {
          return MaterialApp(
            locale: languageProvider.locale,
            supportedLocales: const [
              Locale('en', 'US'),
              Locale('uk', 'UA'),
            ],
            localizationsDelegates: const [
              GlobalMaterialLocalizations.delegate,
              GlobalWidgetsLocalizations.delegate,
              GlobalCupertinoLocalizations.delegate,
            ],
            title: 'Messaging App',
            theme: ThemeData(
              fontFamily: 'VollkornRegular',
              colorScheme: ColorScheme.fromSeed(seedColor: const Color.fromARGB(255, 54, 168, 255)),
            ),
            home: const ConnectionStatusPage(),
          );
        },
      ),
    );
  }
}

class ConnectionStatusPage extends StatefulWidget {
  const ConnectionStatusPage({super.key});

  @override
  ConnectionStatusPageState createState() => ConnectionStatusPageState();
}

class ConnectionStatusPageState extends State<ConnectionStatusPage> {
  bool _isConnected = true;
  late StreamSubscription<List<ConnectivityResult>> _subscription;

  @override
  void initState() {
    super.initState();
    _checkInitialConnection();
    _listenToConnectionChanges();
  }

  Future<void> _checkInitialConnection() async {
    var result = await Connectivity().checkConnectivity();
    _updateConnectionStatus(result.first);
  }

  void _listenToConnectionChanges() {
    _subscription = Connectivity().onConnectivityChanged.listen((result) {
      _updateConnectionStatus(result.first);
    });
  }

  void _updateConnectionStatus(ConnectivityResult result) {
    setState(() {
      _isConnected = (result == ConnectivityResult.wifi || result == ConnectivityResult.mobile);
    });

    if (!_isConnected) {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (context) => const NoConnectionPage()),
      );
    }
  }

  @override
  void dispose() {
    _subscription.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {    
    return _isConnected ? const LoginPage() : const NoConnectionPage();
  }
}

class NoConnectionPage extends StatelessWidget {
  const NoConnectionPage({super.key});

  @override
  Widget build(BuildContext context) {
    ModalRoute.of(context)?.addScopedWillPopCallback(() async {
      return false;
    });

    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.signal_wifi_off, size: 100, color: Colors.grey[500]),
            const SizedBox(height: 20),
            Text("No Internet Connection", style: TextStyle(fontSize: 20, color: Colors.grey[700])),
            const SizedBox(height: 10),
            Text("Please check your network settings", style: TextStyle(color: Colors.grey[600])),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: () => Navigator.pushReplacement(
                context,
                MaterialPageRoute(builder: (context) => const ConnectionStatusPage()),
              ),
              child: const Text("Retry"),
            ),
          ],
        ),
      ),
    );
  }
}
