import 'dart:ffi';

import 'package:messaging_app/models/chat.dart';
import 'package:messaging_app/models/message.dart';

class User {
  int? id;
  String? name;
  String? surname;
  String? username;
  String? profilePhotoLink;
  bool? isOnline;
  List? chats;
  List? unreadMessages;

  User({
    int? id,
    required String this.name,
    String? surname,
    required this.username,
    String? profilePhotoLink,
    bool? isOnline,
    List? chats,
    List? unreadMessages,
  })  : id = id ?? -1,
        surname = surname ?? "",
        profilePhotoLink = profilePhotoLink ?? "assets/letter_images/${name.isNotEmpty ? name[0].toLowerCase() : "u"}.png",
        chats = chats ?? [],
        isOnline = isOnline ?? false,
        unreadMessages = unreadMessages ?? [];

  factory User.fromJson(Map<String, dynamic> json, {bool includeChats=false}) {
    User user = User(
      id: json['id'] ?? -1,
      name: json['name'] ?? "",
      surname: json['surname'] ?? "",
      username: json['username'] ?? "",
      profilePhotoLink: json['profile_photo_link'],
      isOnline: json['is_online'],
      chats: [],
      unreadMessages: (json['unread_messages'] as List<dynamic>?)
          ?.map((m) => Message.fromJson(m))
          .toList() ?? [],
    );

    if (includeChats) {
      user.chats = (json['chats'] as List<dynamic>?)
          ?.map((chat) => Chat.fromJson(chat))
          .toList() ?? [];
    }

    return user;
  }

  User deepCopy() {
    return User(
      id: this.id,
      name: this.name!,
      surname: this.surname,
      username: this.username!,
      profilePhotoLink: this.profilePhotoLink,
      isOnline: this.isOnline,
      chats: this.chats?.map((chat) => chat.deepCopy()).toList(), 
      unreadMessages: List.from(this.unreadMessages!), 
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'surname': surname,
      'username': username,
      'profile_photo_link': profilePhotoLink,
      'last_seen': isOnline,
      // 'chats': chats?.map((chat) => ).toList() ?? [],
      'unread_messages': unreadMessages,
    };
  }
}
