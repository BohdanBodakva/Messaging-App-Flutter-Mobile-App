import 'package:messaging_app/models/user.dart';
import 'package:messaging_app/models/message.dart';

class Chat {
  int? id;
  String? name;
  DateTime? createdAt;
  int? adminId;
  List<User>? users;
  String? chatPhotoLink;
  bool? isGroup;
  List<Message>? messages;

  Chat({
    int? id,
    required String this.name,
    required this.createdAt,
    int? adminId,
    List<User>? users,
    String? chatPhotoLink,
    required this.isGroup,
    List<Message>? messages,
  })  : id = id ?? -1,
        adminId = adminId ?? -1,
        users = users ?? [],
        chatPhotoLink = chatPhotoLink ?? "assets/letter_images/${name.isNotEmpty ? name[0].toLowerCase() : "g"}.png",
        messages = messages ?? [];

  factory Chat.fromJson(Map<String, dynamic> json) {
    return Chat(
      id: json['id'] ?? -1,
      name: json['name'] ?? "",
      createdAt: json['created_at'] != null ? DateTime.parse(json['created_at']) : null,
      adminId: json['admin_id'] ?? -1,
      users: (json['users'] as List<dynamic>?)
          ?.map((user) => User.fromJson(user))
          .toList() ?? [],
      chatPhotoLink: json['chat_photo_link'],
      isGroup: json['is_group'] ?? false,
      messages: (json['messages'] as List<dynamic>?)
          ?.map((msg) => Message.fromJson(msg))
          .toList() ?? [],
    );
  }

  Chat deepCopy() {
    return Chat(
      id: this.id,
      name: this.name!,
      createdAt: this.createdAt,
      adminId: this.adminId,
      users: this.users?.map((user) => user.deepCopy()).toList(), 
      chatPhotoLink: this.chatPhotoLink,
      isGroup: this.isGroup,
      messages: this.messages?.map((msg) => msg.deepCopy()).toList(), 
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'created_at': createdAt?.toIso8601String(),
      'admin_id': adminId,
      'users': users?.map((user) => user.toJson()).toList(),
      'chat_photo_link': chatPhotoLink,
      'is_group': isGroup,
      'messages': messages?.map((msg) => msg.toJson()).toList(),
    };
  }
}
