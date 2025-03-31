import 'dart:core';

List<Map<String, String>> splitTextAndCode(String text) {
  RegExp pattern = RegExp("```.*?```", dotAll: true);
  List<Map<String, String>> parts = [];
  int lastEnd = 0;

  for (RegExpMatch match in pattern.allMatches(text)) {
    int start = match.start;
    int end = match.end;

    if (lastEnd < start) {
      String textPart = text.substring(lastEnd, start).trim();
      if (textPart.isNotEmpty) {
        parts.add({"text": textPart});
      }
    }

    String codePart = text.substring(start + 3, end - 3).trim();
    if (codePart.isNotEmpty) {
      parts.add({"code": codePart});
    }

    lastEnd = end;
  }

  if (lastEnd < text.length) {
    String remainingText = text.substring(lastEnd).trim();
    if (remainingText.isNotEmpty) {
      parts.add({"text": remainingText});
    }
  }

  return parts;
}
