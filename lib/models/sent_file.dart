class SentFile {
  int? id;
  String? fileLink;
  int? messageId;

  SentFile({
    int? id,
    required this.fileLink,
    required this.messageId,
  }) : id = id ?? -1;

  factory SentFile.fromJson(Map<String, dynamic> json) {
    return SentFile(
      id: json['id'] ?? -1,
      fileLink: json['file_link'] ?? "",
      messageId: json['message_id'] ?? -1,
    );
  }

  SentFile deepCopy() {
    return SentFile(
      id: this.id,
      fileLink: this.fileLink!,
      messageId: this.messageId,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'file_link': fileLink,
      'message_id': messageId,
    };
  }
}
