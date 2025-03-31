import 'package:flutter/material.dart';
import 'package:messaging_app/handlers/http_request.dart';
import 'package:messaging_app/handlers/shared_prefs.dart';
import 'package:messaging_app/models/user.dart';
import 'package:messaging_app/pages/chat_list.dart';
import 'package:messaging_app/providers/language_provider.dart';
import 'package:messaging_app/services/hash_service.dart';
import 'package:messaging_app/widgets/error_message.dart';
import 'package:provider/provider.dart';
import 'dart:convert';
import 'package:crypto/crypto.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({super.key, User? currentUser, setCurrentUser});

  @override
  LoginPageState createState() => LoginPageState();
}

class LoginPageState extends State<LoginPage> {
  bool isLoginForm = true;
  bool isLoading = false;
  String error = "";

  bool isNameInputValid = true;
  bool isUsernameInputValid = true;
  bool isPasswordInputValid = true;
  bool isRepeatPasswordInputValid = true;

  bool displaySuccessfulSignupMessage = false;

  void setSuccessfulSignupMessage(bool newValue) {
    setState(() {
      displaySuccessfulSignupMessage = newValue;
    });
  }

  void setNameInputValid(bool newValue) {
    setState(() {
      isNameInputValid = newValue;
    });
  }

  void setUsernameInputValid(bool newValue) {
    setState(() {
      isUsernameInputValid = newValue;
    });
  }

  void setPasswordInputValid(bool newValue) {
    setState(() {
      isPasswordInputValid = newValue;
    });
  }

  void setRepeatPasswordInputValid(bool newValue) {
    setState(() {
      isRepeatPasswordInputValid = newValue;
    });
  }

  @override
  void initState() {
    super.initState();

    // (() async {
    //   await (await SharedPreferences.getInstance()).clear();
    // })();

    setState(() {
      isLoading = true;
    });

    (() async {
      final token = await getDataFromStorage("accessToken");
      final stringUserId = await getDataFromStorage("user_id");

      if (stringUserId == null) return;

      final userId = int.parse(stringUserId);

      if (token != null) {
        Navigator.of(context, rootNavigator: true).push(
          PageRouteBuilder(
            pageBuilder: (context, animation, secondaryAnimation) => ChatListPage(userId: userId,),
            transitionsBuilder: (context, animation, secondaryAnimation, child) {
              const begin = Offset(1.0, 0.0);
              const end = Offset.zero;
              const curve = Curves.easeInOut;

              var tween = Tween(begin: begin, end: end).chain(CurveTween(curve: curve));
              var offsetAnimation = animation.drive(tween);

              return SlideTransition(position: offsetAnimation, child: child);
            },
          ),
        );
      }
    })();

    setState(() {
      isLoading = false;
    });
  }

  void toggleForm() {
    setState(() {
      error = "";
      isLoginForm = !isLoginForm;
    });
  }

  void setLoading(bool newValue) {
    setState(() {
      isLoading = newValue;
    });
  }

  void setError(String newError) {
    setState(() {
      error = newError;
    });
  }

  @override
  Widget build(BuildContext context) {
    ModalRoute.of(context)?.addScopedWillPopCallback(() async {
      return false;
    });

    var languageProvider = Provider.of<LanguageProvider>(context);
    String languageCode = languageProvider.locale.languageCode;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        automaticallyImplyLeading: false,
        title: const Text("Messaging App"),
        centerTitle: true,
      ),
      body: Stack(
        children: [
          GestureDetector(
            onTap: () => FocusScope.of(context).unfocus(),
            child: Center(
              child: SingleChildScrollView(
                child: Padding(
                  padding: const EdgeInsets.all(20.0),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      isLoginForm ? 
                        LoginForm(
                          displaySuccessfulSignupMessage: displaySuccessfulSignupMessage,
                          setSuccessfulSignupMessage: setSuccessfulSignupMessage,
                          toggleForm: toggleForm, 
                          isLoading: isLoading,
                          setLoading: setLoading,
                          error: error, 
                          setError: setError,
                          isUsernameInputValid: isUsernameInputValid,
                          setUsernameInputValid: setUsernameInputValid,
                          isPasswordInputValid: isPasswordInputValid,
                          setPasswordInputValid: setPasswordInputValid,
                        ) : 
                        SignUpForm(
                          setSuccessfulSignupMessage: setSuccessfulSignupMessage,
                          toggleForm: toggleForm, 
                          isLoading: isLoading,
                          setLoading: setLoading, 
                          error: error, 
                          setError: setError,
                          isUsernameInputValid: isUsernameInputValid,
                          setUsernameInputValid: setUsernameInputValid,
                          isPasswordInputValid: isPasswordInputValid,
                          setPasswordInputValid: setPasswordInputValid,
                          isNameInputValid: isNameInputValid,
                          setNameInputValid: setNameInputValid,
                          isRepeatPasswordInputValid: isRepeatPasswordInputValid,
                          setRepeatPasswordInputValid: setRepeatPasswordInputValid,
                        ),
                      const SizedBox(height: 20),
                      TextButton(
                        onPressed: () {
                          if (languageCode == 'en') {
                            languageProvider.setLocale('uk');
                          } else {
                            languageProvider.setLocale('en');
                          }
                        },
                        style: TextButton.styleFrom(
                          backgroundColor: Colors.blue,
                          padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.language, color: Colors.white),
                            const SizedBox(width: 10),
                            Text(
                              languageCode == 'en' ? 'en' : 'укр',
                              style: const TextStyle(color: Colors.white),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
          if (isLoading)
            Container(
              color: Colors.black.withOpacity(0.3),
              child: const Center(
                child: CircularProgressIndicator(),
              ),
            ),
        ],
      ),
    );
  }
}


class LoginForm extends StatelessWidget {
  final bool displaySuccessfulSignupMessage;
  final Function setSuccessfulSignupMessage;

  final VoidCallback toggleForm;
  final bool isLoading;
  final Function setLoading;
  final String error;
  final Function setError;

  final bool isUsernameInputValid;
  final Function setUsernameInputValid;
  final bool isPasswordInputValid;
  final Function setPasswordInputValid;

  final TextEditingController _usernamenameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  LoginForm({
    super.key, 
    required this.displaySuccessfulSignupMessage,
    required this.setSuccessfulSignupMessage,
    required this.toggleForm,
    required this.isLoading,
    required this.setLoading, 
    required this.error,
    required this.setError,
    required this.isUsernameInputValid,
    required this.setUsernameInputValid,
    required this.isPasswordInputValid,
    required this.setPasswordInputValid,
  });

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(languageProvider.localizedStrings['login'] ?? 'Login',
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            textAlign: TextAlign.center),
        const SizedBox(height: 20),
        if (displaySuccessfulSignupMessage) 
          ErrorMessageBox(
            errorMessage: languageProvider.localizedStrings['signupWasSuccessful'] ?? "Sign up is successful. Please, log in", 
            isSuccess: true,
          ),
        if (error.isNotEmpty) 
          ErrorMessageBox(errorMessage: error),
        if (displaySuccessfulSignupMessage || error.isNotEmpty)
          const SizedBox(height: 20),
        TextField(
          controller : _usernamenameController,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['username'] ?? 'Username',
            border: const OutlineInputBorder(),
          ),
        ),
        Visibility(
          visible: !isUsernameInputValid,
          child: Padding(
            padding: const EdgeInsets.only(top: 5.0, left: 5.0),
            child: Text(
              languageProvider.localizedStrings['fieldCannotBeEmpty'] ?? 'The filed cannot be empty', 
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 15),
        TextField(
          controller : _passwordController,
          obscureText: true,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['password'] ?? 'Password',
            border: const OutlineInputBorder(),
          ),
        ),
        Visibility(
          visible: !isPasswordInputValid,
          child: Padding(
            padding: const EdgeInsets.only(top: 5.0, left: 5.0),
            child: Text(
              languageProvider.localizedStrings['fieldCannotBeEmpty'] ?? 'The filed cannot be empty', 
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: () async {
            setError("");
            setSuccessfulSignupMessage(false);
            setUsernameInputValid(true);
            setPasswordInputValid(true);

            String username = _usernamenameController.text;
            String password = _passwordController.text; 

            if (username.isEmpty) {
              setUsernameInputValid(false);
              return;
            } else if (password.isEmpty) {
              setPasswordInputValid(false);
              return;
            }

            setLoading(true);

            var response = await makeHttpRequest(
              "POST", 
              "/auth/login", 
              {
                "username": username,
                "password": hashString(password),
              },
              {}
            );

            final error = response[1];

            if (error == null) {
              await saveDataToStorage("accessToken", response[0]["access_token"]);

              final userId = response[0]["user_id"];
              debugPrint("USER____________ID: $userId");
              await saveDataToStorage("user_id", userId.toString());

              Navigator.of(context, rootNavigator: true).push(
                PageRouteBuilder(
                  pageBuilder: (context, animation, secondaryAnimation) => ChatListPage(userId: userId),
                  transitionsBuilder: (context, animation, secondaryAnimation, child) {
                    const begin = Offset(1.0, 0.0);
                    const end = Offset.zero;
                    const curve = Curves.easeInOut;

                    var tween = Tween(begin: begin, end: end).chain(CurveTween(curve: curve));
                    var offsetAnimation = animation.drive(tween);

                    return SlideTransition(position: offsetAnimation, child: child);
                  },
                ),
              );
            } else {

              try {
                final errorBody = json.decode(error.body);
                final errorStatusCode = error.statusCode;

                if (errorStatusCode == 404){
                  final msg = errorBody["msg"].toString();
                  final username = errorBody["username"].toString();

                  if (msg.toLowerCase().contains("incorrect password")) {
                    setError(languageProvider.localizedStrings['incorrectPassword'] ?? "Incorrect password");
                  } else {
                    setError("$username: ${languageProvider.localizedStrings['userNotFound'] ?? "user dosn't exist"}");
                  }

                } else {
                  setError(error.body.toString());
                }
              } catch (e) {
                setError(e.toString());
              }
              
            }

            setLoading(false);
          },
          style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0072FF)),
          child: Text(
            languageProvider.localizedStrings['login'] ?? 'Login',
            style: const TextStyle(color: Color.fromARGB(255, 255, 255, 255)),
          ),
        ),
        const SizedBox(height: 10),
        TextButton(
          onPressed: () {
            setError("");

            setSuccessfulSignupMessage(false);

            setUsernameInputValid(true);
            setPasswordInputValid(true);

            toggleForm();
          },
          child: SizedBox(
            width: MediaQuery.of(context).size.width * 0.6,
            child: Text(
              languageProvider.localizedStrings['loginCheckoutMessage'] ?? "Don't have an account? Sign Up", 
              style: const TextStyle(color: Color(0xFF0072FF)),
              textAlign: TextAlign.center,
              softWrap: true,
            ),
          ),
        ),
      ],
    );
  }
}

class SignUpForm extends StatelessWidget {
  final Function setSuccessfulSignupMessage;

  final VoidCallback toggleForm;
  final bool isLoading;
  final Function setLoading;
  final String error;
  final Function setError;

  final bool isUsernameInputValid;
  final Function setUsernameInputValid;
  final bool isPasswordInputValid;
  final Function setPasswordInputValid;
  final bool isNameInputValid;
  final Function setNameInputValid;
  final bool isRepeatPasswordInputValid;
  final Function setRepeatPasswordInputValid;

  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _surnameController = TextEditingController();
  final TextEditingController _usernamenameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _repeatPasswordController = TextEditingController();

  SignUpForm({
    super.key, 
    required this.setSuccessfulSignupMessage,
    required this.toggleForm, 
    required this.isLoading,
    required this.setLoading, 
    required this.error,
    required this.setError,
    required this.isUsernameInputValid,
    required this.setUsernameInputValid,
    required this.isPasswordInputValid,
    required this.setPasswordInputValid,
    required this.isNameInputValid,
    required this.setNameInputValid,
    required this.isRepeatPasswordInputValid,
    required this.setRepeatPasswordInputValid,
  });

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(languageProvider.localizedStrings['signup'] ?? 'Sign Up',
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            textAlign: TextAlign.center),
        const SizedBox(height: 20),
        if (error.isNotEmpty) 
          ErrorMessageBox(errorMessage: error),
        if (error.isNotEmpty)
          const SizedBox(height: 20),
        TextField(
          controller: _nameController,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['name'] ?? 'First Name',
            border: const OutlineInputBorder(),
          ),
        ),
        Visibility(
          visible: !isNameInputValid,
          child: Padding(
            padding: const EdgeInsets.only(top: 5.0, left: 5.0),
            child: Text(
              languageProvider.localizedStrings['fieldCannotBeEmpty'] ?? 'The filed cannot be empty', 
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 15),
        TextField(
          controller: _surnameController,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['surname'] ?? 'Last Name',
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 15),
        TextField(
          controller: _usernamenameController,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['username'] ?? 'Username',
            border: const OutlineInputBorder(),
          ),
        ),
        Visibility(
          visible: !isUsernameInputValid,
          child: Padding(
            padding: const EdgeInsets.only(top: 5.0, left: 5.0),
            child: Text(
              languageProvider.localizedStrings['fieldCannotBeEmpty'] ?? 'The filed cannot be empty', 
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 15),
        TextField(
          controller: _passwordController,
          obscureText: true,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['password'] ?? 'Password',
            border: const OutlineInputBorder(),
          ),
        ),
        Visibility(
          visible: !isPasswordInputValid,
          child: Padding(
            padding: const EdgeInsets.only(top: 5.0, left: 5.0),
            child: Text(
              languageProvider.localizedStrings['fieldCannotBeEmpty'] ?? 'The filed cannot be empty', 
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 15),
        TextField(
          controller: _repeatPasswordController,
          obscureText: true,
          decoration: InputDecoration(
            labelText: languageProvider.localizedStrings['repeatPassword'] ?? 'Repeat Password',
            border: const OutlineInputBorder(),
          ),
        ),
        Visibility(
          visible: !isRepeatPasswordInputValid,
          child: Padding(
            padding: const EdgeInsets.only(top: 5.0, left: 5.0),
            child: Text(
              languageProvider.localizedStrings['passwordsDoesNotMatch'] ?? "Passwords don't match", 
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: () async {
            setNameInputValid(true);
            setPasswordInputValid(true);
            setUsernameInputValid(true);
            setRepeatPasswordInputValid(true);

            String name = _nameController.text;
            String surname = _surnameController.text; 
            String username = _usernamenameController.text;
            String password = _passwordController.text; 
            String repeatPassword = _repeatPasswordController.text;

            if (name.isEmpty) {
              setNameInputValid(false);
              return;
            } else if (username.isEmpty) {
              setUsernameInputValid(false);
              return;
            } else if (password.isEmpty) {
              setPasswordInputValid(false);
              return;
            } else if (repeatPassword != password) {
              setRepeatPasswordInputValid(false);
              return;
            }

            setLoading(true);

            var response = await makeHttpRequest(
              "POST", 
              "/auth/signup", 
              {
                "name": name,
                "surname": surname,
                "username": username,
                "password": hashString(password),
              },
              {}
            );

            final error = response[1];

            if (error == null) {
              setSuccessfulSignupMessage(true);
              toggleForm();
            } else {

              try {
                final errorBody = json.decode(error.body);
                final errorStatusCode = error.statusCode;

                if (errorStatusCode == 409){
                  final msg = errorBody["msg"].toString();
                  final username = errorBody["username"].toString();

                  if (msg.toLowerCase().contains("already exists")) {
                    setError(languageProvider.localizedStrings['userAlredyExists'] ?? "User with such username already exists");
                  } else {
                    setError(error.body.toString());
                  }

                } else {
                  setError(error.body.toString());
                }
              } catch (e) {
                setError(e.toString());
              }
              
            }

            setLoading(false);
          },
          style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0072FF)),
          child: Text(
            languageProvider.localizedStrings['signup'] ?? 'Sign Up',
            style: const TextStyle(color: Color.fromARGB(255, 255, 255, 255)),
          ),
        ),
        const SizedBox(height: 10),
        TextButton(
          onPressed: () {
            setError("");

            setSuccessfulSignupMessage(false);

            setNameInputValid(true);
            setUsernameInputValid(true);
            setPasswordInputValid(true);
            setRepeatPasswordInputValid(true);

            toggleForm();
          },
          child: SizedBox(
            width: MediaQuery.of(context).size.width * 0.6,
            child: Text(
              languageProvider.localizedStrings['signupCheckoutMessage'] ?? "Already have an account? Login", 
              style: const TextStyle(color: Color(0xFF0072FF)),
              textAlign: TextAlign.center,
              softWrap: true,
            ),
          ),
        ),
      ],
    );
  }
}
