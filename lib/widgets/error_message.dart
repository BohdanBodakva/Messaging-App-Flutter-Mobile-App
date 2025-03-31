import 'package:flutter/material.dart';
import 'package:messaging_app/providers/language_provider.dart';
import 'package:provider/provider.dart';

class ErrorMessageBox extends StatelessWidget {
  final String errorMessage;
  final bool isSuccess;

  const ErrorMessageBox({
    Key? key,
    required this.errorMessage,
    this.isSuccess = false,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);

    final boxColor = isSuccess ? Colors.green.shade100 : Colors.red.shade100;
    final borderColor = isSuccess ? Colors.green : Colors.red;
    final iconColor = isSuccess ? Colors.green : Colors.red;
    final textColor = isSuccess ? Colors.green : Colors.red;

    return Container(
      decoration: BoxDecoration(
        color: boxColor,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: borderColor,
          width: 1.5,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 12),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              Icons.error_outline,
              color: iconColor,
              size: 20,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    isSuccess ? 
                      "${languageProvider.localizedStrings['info'] ?? 'Info'}: " :
                      "${languageProvider.localizedStrings['error'] ?? 'Error'}: ",
                    style: TextStyle(
                      color: textColor,
                      fontSize: 14,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    errorMessage,
                    style: TextStyle(
                      color: textColor,
                      fontSize: 14,
                    ),
                    softWrap: true,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
