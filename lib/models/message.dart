import 'package:messaging_app/models/sent_file.dart';
import 'package:messaging_app/models/user.dart';

class Message {
  int? id;
  String? text;
  List<SentFile>? sentFiles;
  DateTime? sendAt;
  List<User>? usersThatUnread;
  bool? isHidden;
  int? userId;
  int? chatId;

  Message({
    int? id,
    required this.text,
    List<SentFile>? sentFiles,
    required this.sendAt,
    List<User>? usersThatUnread,
    bool? isHidden,
    int? userId,
    required this.chatId,
  })  : id = id ?? -1,
        sentFiles = sentFiles ?? [],
        usersThatUnread = usersThatUnread ?? [],
        isHidden = isHidden ?? false,
        userId = userId ?? -1;

  factory Message.fromJson(Map<String, dynamic> json) {
    return Message(
      id: json['id'] ?? -1,
      text: json['text'] ?? "",
      sentFiles: (json['sent_files'] as List<dynamic>?)
          ?.map((file) => SentFile.fromJson(file))
          .toList() ?? [],
      sendAt: json['send_at'] != null ? DateTime.parse(json['send_at']) : null,
      usersThatUnread: (json['users_that_unread'] as List<dynamic>?)
          ?.map((user) => User.fromJson(user))
          .toList() ?? [],
      isHidden: json['is_hidden'] ?? false,
      userId: json['user_id'] ?? -1,
      chatId: json['chat_id'] ?? -1,
    );
  }

  Message deepCopy() {
    return Message(
      id: this.id,
      text: this.text!,
      sentFiles: this.sentFiles?.map((file) => file.deepCopy()).toList(), 
      sendAt: this.sendAt,
      usersThatUnread: this.usersThatUnread?.map((user) => user.deepCopy()).toList(), 
      isHidden: this.isHidden,
      userId: this.userId,
      chatId: this.chatId,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'text': text,
      'sent_files': sentFiles?.map((file) => file.toJson()).toList(),
      'send_at': sendAt?.toIso8601String(),
      'users_that_unread': usersThatUnread?.map((user) => user.toJson()).toList(),
      "is_hidden": isHidden,
      'user_id': userId,
      'chat_id': chatId,
    };
  }
}
