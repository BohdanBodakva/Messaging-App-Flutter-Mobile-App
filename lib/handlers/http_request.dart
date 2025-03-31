import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:messaging_app/handlers/shared_prefs.dart';

const backendUrl = "http://192.168.0.104:5001";

Future makeRequestToBackend(String method, String url, body, Map<String, String> headers) async {
  method = method.toUpperCase();
  Map<String, String> requestHeaders = {};
  final fullUrl = Uri.parse("$backendUrl$url");

  var accessToken = await getDataFromStorage("access_token");

  const authUrls = ["/auth/login", "/auth/signup"];
  if (!authUrls.contains(url)) {
    if (headers.isNotEmpty) {
      requestHeaders = headers;
    }
    requestHeaders["Authorization"] = "Bearer $accessToken";
  }

  requestHeaders["Accept"] = "application/json";
  requestHeaders["content-type"] = "application/json";

  if (method == "GET") {
    return await http.get(
        fullUrl,
        headers: requestHeaders,
      );
  }
  else if (method == "POST") {
    return await http.post(
        fullUrl,
        body: json.encode(body),
        headers: requestHeaders,
      );
  }
  else if (method == "PUT") {
    return await http.put(
        fullUrl,
        body: json.encode(body),
        headers: requestHeaders,
      );
  }
  else if (method == "PATCH") {
    return await http.patch(
        fullUrl,
        body: json.encode(body),
        headers: requestHeaders,
      );
  }
  else if (method == "DELETE") {
    return await http.delete(
        fullUrl,
        body: json.encode(body),
        headers: requestHeaders,
      );
  }
  else {
    throw Exception("Invalid HTTP method!");
  }
}

Future makeHttpRequest(String method, String url, body, Map<String, String> headers) async {
  var result;
  var error;

  try {
    final response = await makeRequestToBackend(method, url, body, headers);

    if (response.statusCode >= 200 && response.statusCode < 300) {
      result = json.decode(response.body);
    } else {

      // refresh access_token
      if (response.statusCode == 401 && response.data.msg == "Expired token") {

        var refreshToken = await getDataFromStorage("refresh_token");
        if (refreshToken == null){
          error = "refresh_token is missing";
        } else {
          try {
            final refreshTokenUrl = Uri.parse("$backendUrl/auth/refresh");
            final response = await http.post(
              refreshTokenUrl,
              body: {},
              headers: {"Authorization": "Bearer $refreshToken"},
            );

            if (response.statusCode >= 200 && response.statusCode < 300) {
              String newAccessToken = json.decode(response.body).access_token.toString();
              await saveDataToStorage("access_token", newAccessToken);

              // repeat request with new access_token
              try {
                final response = await makeRequestToBackend(method, url, body, headers);

                if (response.statusCode >= 200 && response.statusCode < 300) {
                  result = json.decode(response.body);
                } else {
                  error = response;
                }
              } catch (e) {
                error = e.toString();
              }

            } else {
              error = response;
            }
          } catch (e) {
            error = e.toString();
          }
        }

      } else {
        error = response;
      }

    }
  } catch (e) {
    error = e.toString();
  }

  return [result, error];
}
