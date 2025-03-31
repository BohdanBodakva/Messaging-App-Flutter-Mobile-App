import 'package:flutter/material.dart';
import 'package:messaging_app/models/chat.dart';
import 'package:messaging_app/models/user.dart';
import 'package:messaging_app/providers/language_provider.dart';
import 'package:provider/provider.dart';
import 'package:socket_io_client/socket_io_client.dart';

class ChatInfoPage extends StatefulWidget {
  final bool isGroup;
  final List<User>? users;
  final Chat chat;
  final Socket socket;
  final Function clearChatHistory;
  final bool chatWithAI;

  const ChatInfoPage({super.key, required this.socket, required this.isGroup, required this.users, required this.chat, required this.clearChatHistory, this.chatWithAI=false});

  @override
  ChatInfoPageState createState() => ChatInfoPageState();
}

class ChatInfoPageState extends State<ChatInfoPage> {
  bool isLoading = false;

  @override
  void initState() {
    super.initState();

    setState(() {
      isLoading = false;
    });
    
    _defineWebsocketOperation();
  }

  _defineWebsocketOperation(){
    (() async {
      await _defineWebsocketEvents();
    })();
  }

  Future<void> _defineWebsocketEvents() async {
    widget.socket.on("delete_chat_from_chat_info", (data) {
      Navigator.pop(context);
    });

    widget.socket.on("clear_chat_history", (data) {
      setState(() {
        isLoading = false;
      });
    });
  }

  @override
  void dispose() {
    widget.socket.off("delete_chat_from_chat_info");
    widget.socket.off("clear_chat_history");

    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(languageProvider.localizedStrings['userInfo'] ?? "User Info"),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        centerTitle: true,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Stack(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              children: [
                CircleAvatar(
                  radius: 50,
                  backgroundImage: widget.users![0].profilePhotoLink != null && !widget.users![0].profilePhotoLink!.contains("assets/letter_images")
                    ? NetworkImage(widget.users![0].profilePhotoLink!)  as ImageProvider<Object>
                    : AssetImage(widget.users![0].profilePhotoLink ?? "assets/letter_images/u.png") as ImageProvider<Object>,
                ),
                const SizedBox(height: 16),
                
                if (!widget.isGroup)
                  _buildInfoRow(languageProvider.localizedStrings['name'] ?? "Name", widget.users![0].name!),
                if (!widget.isGroup)
                  _buildInfoRow(languageProvider.localizedStrings['surname'] ?? "Surname", widget.users![0].surname!),
                if (!widget.isGroup)
                  _buildInfoRow(languageProvider.localizedStrings['username'] ?? "Username", "@${widget.users![0].username}"),

                const SizedBox(height: 20),

                if (!widget.isGroup && !widget.chatWithAI)
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      onPressed: () async => {
                        await _showDeleteChatDialog(widget.socket), 
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.red,
                      ),
                      child: Text(languageProvider.localizedStrings['deleteChat'] ?? "Delete Chat"),
                    ),
                  ),
                if (widget.chatWithAI)
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      onPressed: () async => {
                        _showDeleteChatHistoryDialog(widget.socket), 
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color.fromARGB(255, 192, 192, 192),
                      ),
                      child: Text(languageProvider.localizedStrings['clearChatHistory'] ?? "Clear Chat History"),
                    ),
                  ),
              ],
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

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontWeight: FontWeight.bold)),
          Text(value),
        ],
      ),
    );
  }

  Future<void> _showDeleteChatDialog(Socket socket) async {
    var languageProvider = Provider.of<LanguageProvider>(context, listen: false);

    await showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(languageProvider.localizedStrings['deleteChat'] ?? "Delete Chat"),
        content: Text(languageProvider.localizedStrings['deleteChatConfirmMessage'] ?? "Are you sure you want to clear chat history?"),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(languageProvider.localizedStrings['cancel'] ?? "Cancel"),
          ),
          ElevatedButton(
            onPressed: () {
              socket.emit("delete_chat", {
                "chat_id": widget.chat.id
              });

              Navigator.pop(context);
            },
            child: Text(languageProvider.localizedStrings['delete'] ?? "Delete"),
          ),
        ],
      ),
    );
  }

  Future<void> _showDeleteChatHistoryDialog(Socket socket) async {
    var languageProvider = Provider.of<LanguageProvider>(context, listen: false);

    await showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(languageProvider.localizedStrings['clearChatHistory'] ?? "Clear Chat History"),
        content: Text(languageProvider.localizedStrings['clearChatHistoryConfrimMessage'] ?? "Are you sure you want to clear chat history?"),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(languageProvider.localizedStrings['cancel'] ?? "Cancel"),
          ),
          ElevatedButton(
            onPressed: () {
              setState(() {
                widget.clearChatHistory();
              });

              setState(() {
                isLoading = true;
              });

              socket.emit("clear_chat_history", {
                "chat_id": widget.chat.id
              });

              Navigator.pop(context);
            },
            child: Text(languageProvider.localizedStrings['clear'] ?? "Clear"),
          ),
        ],
      ),
    );
  }
}
