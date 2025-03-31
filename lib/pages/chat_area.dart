import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:image_picker/image_picker.dart';
import 'package:messaging_app/handlers/date_time.dart';
import 'package:messaging_app/handlers/text_code_interpret.dart';
import 'package:messaging_app/models/chat.dart';
import 'package:messaging_app/models/message.dart';
import 'package:messaging_app/models/user.dart';
import 'package:messaging_app/pages/chat_info_page.dart';
import 'package:messaging_app/pages/group_page.dart';
import 'package:messaging_app/providers/language_provider.dart';
import 'package:messaging_app/widgets/ai_chat_assistant.dart';
import 'package:provider/provider.dart';
import 'package:socket_io_client/socket_io_client.dart';

class ChatPage extends StatefulWidget {
  final Chat chat;
  User? currentUser;
  Function setCurrentUser;
  Socket socket;
  bool chatWithAI;

  ChatPage({super.key, required this.socket, required this.chat, required this.currentUser, required this.setCurrentUser, this.chatWithAI=false});

  @override
  ChatPageState createState() => ChatPageState();
}

class ChatPageState extends State<ChatPage> {
  bool isAIassistantWindowsDisplayed = false;

  closeAIAssistantWindow() {
    setState(() {
      isAIassistantWindowsDisplayed = false;
    });
  }

  bool isListening = false;
  bool isLoading = true;

  bool isTyping = false;
  String fullUserNameTyping = "";

  User? currentUserChatPage;
  Chat? currentChat;

  List<Message> chatHistory = [];
  final itemsCount = 11;
  int loadHistoryOffset = 0;
  bool isChatHistoryEnded = false;

  clearChatHistory() {
    setState(() {
      chatHistory = [];
      loadHistoryOffset = 0;
    });
  }

  final TextEditingController _messageController = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  late bool isGroup;
  late List<User>? otherUsers;
  late String chatName;

  void _onScroll() {
  if (_scrollController.position.pixels <= 0) {
    if (isChatHistoryEnded) {
      return;
    }

    widget.socket.emit("load_chat_history", {
      "chat_id": widget.chat.id,
      "items_count": itemsCount,
      "offset": loadHistoryOffset
    });

    loadHistoryOffset += itemsCount;
  }
}

  @override
  void initState() {
    super.initState();

    WidgetsBinding.instance.addPostFrameCallback((_) {
      _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
    });

    _scrollController.addListener(_onScroll);

    setState(() {
      currentUserChatPage = widget.currentUser!.deepCopy();
      currentChat = widget.chat.deepCopy();
    });

    isGroup = currentChat!.isGroup!;
    otherUsers = currentChat!.users!.where((user) => user.id != currentUserChatPage!.id).toList();

    if (isGroup) {
      chatName = currentChat!.name!;
    } else {
      chatName = currentUserChatPage!.name!;
    }
    
    _loadChatHistory();
  }

  _loadChatHistory(){
    (() async {
      await _defineSocketEvents();
    })();
  }

  Future<void> _defineSocketEvents() async {
    widget.socket.on("load_chat_history", (data) {
      if (isChatHistoryEnded) {
        return;
      }

      final history = (data["chat_history"] as List).map((msg) => Message.fromJson(msg)).toList();
      final isEnd = data["is_end"].toString().toLowerCase() == "true";

      print("IS ENDDDDDDDDDDDDDDDDDDDD: ${isEnd}");

      if (!mounted) return;

      setState(() {
        chatHistory = [...history, ...chatHistory];
      });

      if (isLoading) {
        setState(() {
          isLoading = false;
        });

        WidgetsBinding.instance.addPostFrameCallback((_) {
          _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
        });
      }

      if (isEnd) {
        setState(() {
          isChatHistoryEnded = true;
        });
      }
    });

    widget.socket.on("delete_chat", (data) {
      final chatId = data["chat_id"];

      if (chatId == currentChat!.id) {
        Navigator.pop(context);
      }
    });

    // widget.socket.on("read_chat_history", (data) {
    //   widget.socket.emit(
    //     "load_user", 
    //     {"user_id": widget.currentUser!.id}
    //   );
    // });

    widget.socket.on("leave_group_from_chat_area", (data) {
      final userId = data["user_id"];
      final chatId = data["chat_id"];

      if (userId == widget.currentUser!.id && widget.currentUser!.chats!.map((c) => c.id).toList().contains(chatId)) {
        Navigator.pop(context);
      }
    });  

    widget.socket.on("change_group_info_from_chat_area", (data) {
      Chat group = Chat.fromJson(data["updated_group"]);

      if (group.id == widget.chat.id) {
        final groupUsersIds = group.users!.map((u) => u.id).toList();

        if (group.adminId == widget.currentUser!.id) {
          
        } else {
          if (!groupUsersIds.contains(widget.currentUser!.id)) {
            Navigator.pop(context);
          }
        }
      }
    });

    widget.socket.on('send_message', (data) {
      final message = Message.fromJson(data['message']);
      final room = data['room'];

      User newUser = currentUserChatPage!.deepCopy();
      newUser.chats = [
        newUser.chats!.where((c) => c.id == widget.chat.id).first, 
        ...newUser.chats!.where((c) => c.id != widget.chat.id)
      ];
      newUser.chats![0].messages = [message];

      if (!mounted) return;

      widget.setCurrentUser(newUser);
      setState(() {
        currentUserChatPage = newUser;
      });

      if (currentChat!.id == room) {
        setState(() {
          chatHistory = [...chatHistory, message];
        });

        WidgetsBinding.instance.addPostFrameCallback((_) {
          _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
        });
      } else {
        // MAKE NOTIFICATION
      }
      
    });

    widget.socket.on("user_typing", (data) {
      final userId = data["user_id"];
      final name = data["name"];
      final surname = data["surname"];

      if (userId == currentUserChatPage!.id) return;

      if (!mounted) return;

      setState(() {
        isTyping = true;
        fullUserNameTyping = "$name $surname";
      });

      // Hide "typing" status after 2 seconds
      Future.delayed(const Duration(seconds: 2), () {
        setState(() {
          isTyping = false;
          fullUserNameTyping = "";
        });
      });
    });

    widget.socket.on('delete_message', (data) {
      final messageId = data['message_id'];

      setState(() {
        chatHistory = List.from(chatHistory.where((m) => m.id != messageId));
        _selectedDeleteIndex = null;
      });
    });

    widget.socket.emit("load_chat_history", {
      "chat_id": currentChat!.id,
      "items_count": itemsCount,
      "offset": loadHistoryOffset
    });

    loadHistoryOffset += itemsCount;
  }

  int? _selectedDeleteIndex;

  Future<void> _pickFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();
    if (result != null) {
      print('File picked: ${result.files.single.name}');
    }
  }

  Future<void> _pickImage() async {
    final picker = ImagePicker();
    final XFile? image = await picker.pickImage(source: ImageSource.gallery);
    if (image != null) {
      print('Image picked: ${image.path}');
    }
  }

  void _handleSend() {
    if (_messageController.text.isNotEmpty) {
      String messageText = _messageController.text.trim();

      if (widget.chatWithAI) {
        widget.socket.emit("ai_chat", {
          "prompt": messageText,
          "sent_at": DateTime.now().toIso8601String(),
          "user_id": currentUserChatPage!.id,
          "chat_id": currentChat!.id
        }); 
      } else {
        widget.socket.emit("send_message", {
          "text": messageText,
          "sent_at": DateTime.now().toIso8601String(),
          "sent_files": [],
          "user_id": currentUserChatPage!.id,
          "room": currentChat!.id
        });

        widget.socket.emit("read_chat_history", {
          "user_id": widget.currentUser!.id,
          "chat_id": widget.chat.id
        });
      }

      _messageController.clear();
      _scrollToBottom();
    }
  }

  void _scrollToBottom() {
    _scrollController.animateTo(
      _scrollController.position.maxScrollExtent,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeInOut,
    );
  }

  void _deleteMessage(int index) {
    widget.socket.emit("delete_message", {
      "message_id": index,
      "room": currentChat!.id
    });
  }

  @override
  void dispose() {
    widget.socket.off("load_chat_history");
    widget.socket.off("send_message");
    widget.socket.off("delete_message");
    widget.socket.off("delete_chat");
    widget.socket.off("leave_group_from_chat_area");
    widget.socket.off("user_typing");
    // widget.socket.off("read_chat_history");

    _scrollController.removeListener(_onScroll);
    _scrollController.removeListener(_scrollToBottom);
    _scrollController.dispose();
    super.dispose();
  }

  void sendTypingEvent() {
    widget.socket.emit(
      'typing', 
      {
        'user_id': currentUserChatPage!.id, 
        "chat_id": currentChat!.id
      }
    );
  }

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);

    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        leadingWidth: 100,
        title: Center(
          child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            GestureDetector(
              onTap: () {
                Navigator.of(context, rootNavigator: true).push(
                  PageRouteBuilder(
                    pageBuilder: (context, animation, secondaryAnimation) => 
                      isGroup ? 
                      NewGroupPage(
                        socket: widget.socket, currentUser: widget.currentUser, setCurrentUser: widget.setCurrentUser, isEditing: true, group: widget.chat, openGroupChat: (){},
                      ) :
                      ChatInfoPage(
                        socket: widget.socket, isGroup: isGroup, users: otherUsers, chat: currentChat!, clearChatHistory: clearChatHistory, chatWithAI: widget.chatWithAI
                      ),
                    transitionsBuilder: (context, animation, secondaryAnimation, child) {
                      const begin = Offset(1.0, 0.0);
                      const end = Offset.zero;
                      const curve = Curves.easeInOut;

                      var tween = Tween(begin: begin, end: end).chain(CurveTween(curve: curve));
                      var offsetAnimation = animation.drive(tween);

                      return SlideTransition(position: offsetAnimation, child: child);
                    },
                  )
                );
              },
              child: Row(
                children: [
                  if (widget.chat.isGroup!)
                    const Icon(Icons.group),
                  if (widget.chat.isGroup!)
                    const SizedBox(width: 7),
                  Column(
                    children: [
                      Text(
                        isGroup ? chatName : "${otherUsers![0].name} ${otherUsers![0].surname}", 
                        style: const TextStyle(fontSize: 18)
                      ),
                      if (isTyping)
                        Text(
                          !isGroup ? 
                            "${languageProvider.localizedStrings["typing"]}..." : 
                            "$fullUserNameTyping ${languageProvider.localizedStrings["isTyping"]}...", 
                          style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.bold,
                            color: Colors.white
                          )
                        ),    
                    ],
                  ),
                ],
              ),
            )
          ],
        ),
        ),
        leading: Row(
          mainAxisAlignment: MainAxisAlignment.start,
          children: [
            Container(
              child: IconButton(
                icon: const Icon(Icons.arrow_back),
                onPressed: () {
                  widget.socket.off("load_chat_history");
                  widget.socket.off("send_message");
                  widget.socket.off("delete_message");
                  widget.socket.off("delete_chat");
                  widget.socket.off("leave_group_from_chats");

                  widget.socket.emit("read_chat_history", {
                    "user_id": widget.currentUser!.id,
                    "chat_id": widget.chat.id
                  });
                  widget.socket.emit(
                    "load_user", 
                    {"user_id": widget.currentUser!.id}
                  );

                  Navigator.of(context, rootNavigator: true).pop();
                },
              ),
            ),
            if (!widget.chatWithAI)
              Container(
                child: IconButton(
                  icon: const Icon(Icons.memory),
                  onPressed: () {
                    setState(() {
                      isAIassistantWindowsDisplayed = true;
                    });
                  },
                ),
              ),
          ],
        ),
        actions: [
          GestureDetector(
            onTap: () {
              Navigator.of(context, rootNavigator: true).push(
                PageRouteBuilder(
                  pageBuilder: (context, animation, secondaryAnimation) => 
                    isGroup ? 
                    NewGroupPage(
                      socket: widget.socket, currentUser: widget.currentUser, setCurrentUser: widget.setCurrentUser, isEditing: true, group: widget.chat, openGroupChat: (){},
                    ) :
                    ChatInfoPage(
                      socket: widget.socket, isGroup: isGroup, users: otherUsers, chat: currentChat!, clearChatHistory: clearChatHistory, chatWithAI: widget.chatWithAI
                    ),
                  transitionsBuilder: (context, animation, secondaryAnimation, child) {
                    const begin = Offset(1.0, 0.0);
                    const end = Offset.zero;
                    const curve = Curves.easeInOut;

                    var tween = Tween(begin: begin, end: end).chain(CurveTween(curve: curve));
                    var offsetAnimation = animation.drive(tween);

                    return SlideTransition(position: offsetAnimation, child: child);
                  },
                )
              );
            },
            child: Row(
              children: [
                IconButton(
                  icon: Icon(Icons.clear, color: Colors.transparent),
                  onPressed: () => null,
                ),
                Container(
                margin: const EdgeInsets.only(right: 14.0),
                child: CircleAvatar(
                  radius: 20,
                  backgroundImage: otherUsers![0].profilePhotoLink != null && !otherUsers![0].profilePhotoLink!.contains("assets/letter_images")
                    ? NetworkImage(otherUsers![0].profilePhotoLink!)  as ImageProvider<Object>
                    : AssetImage(otherUsers?[0].profilePhotoLink ?? "assets/letter_images/u.png") as ImageProvider<Object>,
                ),
                )
              ],
            )
          )
        ],
        automaticallyImplyLeading: false,
        centerTitle: true,
      ),
      body: Stack(
        children: [
          GestureDetector(
            onTap: () {
              setState(() {
                _selectedDeleteIndex = null;
              });
            },
            child: Column(
              children: [
                const SizedBox(height: 5,),
                Expanded(
                  child: ListView.builder(
                    controller: _scrollController,
                    itemCount: chatHistory.length,
                    itemBuilder: (context, index) {
                      final prevMessageId = index > 0 ? chatHistory[index - 1].id : null;
                      final currMessageId = chatHistory[index].id;

                      final unreadMessagesIds = currentUserChatPage!.unreadMessages!.map((m) => m.id).toList();

                      return Column (
                        children: [
                          if (prevMessageId != null && unreadMessagesIds.contains(currMessageId) && !unreadMessagesIds.contains(prevMessageId))
                            Row(
                              children: [
                                const Expanded(
                                  child: Divider(
                                    color: Colors.blue,
                                    thickness: 1,
                                    indent: 25,
                                    endIndent: 10,
                                  ),
                                ),
                                Text(
                                  languageProvider.localizedStrings["new"] ?? "New",
                                  style: const TextStyle(
                                    fontSize: 14, 
                                    fontWeight: FontWeight.w200,
                                    color: Colors.blue
                                  ),
                                ),
                                const Expanded(
                                  child: Divider(
                                    color: Colors.blue,
                                    thickness: 1,
                                    indent: 10,
                                    endIndent: 25,
                                  ),
                                ),
                              ],
                            ),
                          ChatMessageItem(
                            index: chatHistory[index].id!,
                            message: chatHistory[index],
                            currentUser: currentUserChatPage!,
                            chat: currentChat!,
                            isGroup: currentChat!.isGroup!,
                            isSelectedForDeletion: _selectedDeleteIndex == chatHistory[index].id!,
                            onDelete: () => _deleteMessage(chatHistory[index].id!),
                            onLongPress: () {
                              if (chatHistory[index].userId! == currentUserChatPage!.id) {
                                if (!widget.chatWithAI) {
                                  setState(() {
                                    _selectedDeleteIndex = chatHistory[index].id!;
                                  });
                                }
                              }
                            },
                          )
                        ],
                      );
                    },
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: Row(
                    children: [
                      if (!widget.chatWithAI)
                        IconButton(
                          icon: const Icon(Icons.image),
                          onPressed: _pickImage,
                        ),
                      Expanded(
                        child: TextField(
                          controller: _messageController,
                          maxLines: null,
                          keyboardType: TextInputType.multiline,
                          onChanged: (text) {
                            if (text.isNotEmpty) sendTypingEvent();
                          },
                          decoration: InputDecoration(
                            hintText: "${languageProvider.localizedStrings['typeMessage']}...",
                            border: const OutlineInputBorder(),
                            contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 15),
                          ),
                          textInputAction: TextInputAction.newline,
                          onSubmitted: (_) => _handleSend(),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.send),
                        onPressed: _handleSend,
                      ),
                    ],
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
          if (isAIassistantWindowsDisplayed)
            CounterPopup(chatId: widget.chat.id, socket: widget.socket, oldContext: context, closeAIAssistantWindow: closeAIAssistantWindow)
        ],
      ),
    );
  }
}

class ChatMessageItem extends StatelessWidget {
  final int index;
  final Message message;
  final User? currentUser;
  final bool isSelectedForDeletion;
  final VoidCallback onDelete;
  final VoidCallback onLongPress;
  final bool isMyMessage;
  final bool isGroup;
  final Chat chat;
  final User user;

  ChatMessageItem({
    super.key,
    required this.index,
    required this.message,
    required this.currentUser,
    required this.chat,
    required this.isGroup,
    required this.isSelectedForDeletion,
    required this.onDelete,
    required this.onLongPress,
  }) : isMyMessage = message.userId == currentUser!.id,
       user = chat.users!.firstWhere((user) => user.id == message.userId);

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);
    String formattedTime = formatDateTime(message.sendAt!);

    return GestureDetector(
      onLongPress: onLongPress,
      child: Align(
        alignment: isMyMessage ? Alignment.centerRight : Alignment.centerLeft,
        child: IntrinsicWidth(
          child: Container(
            margin: const EdgeInsets.symmetric(vertical: 5, horizontal: 10),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: isSelectedForDeletion
                  ? Colors.red
                  : (isMyMessage ? Colors.blueAccent : Colors.grey[300]),
              borderRadius: BorderRadius.circular(12),
            ),
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.7,
            ),
            child: isSelectedForDeletion
                ? GestureDetector(
                    onTap: onDelete,
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.delete, color: Colors.white),
                        const SizedBox(width: 5),
                        Text(
                          languageProvider.localizedStrings['delete'] ?? "Delete",
                          style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  )
                : Column(
                    crossAxisAlignment:
                        isMyMessage ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                    children: [
                      if (isGroup && !isMyMessage)
                        Padding(
                          padding: const EdgeInsets.only(bottom: 2),
                          child: Text(
                            "${user.name} ${user.surname}",
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: isMyMessage ? Colors.white : Colors.black,
                              fontSize: 14,
                              backgroundColor: Color.fromARGB(255, 51, 51, 51),
                            ),
                          ),
                        ),
                      ...splitTextAndCode(message.text!).map((part) {
                        if (part.containsKey("code")) {
                          return Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(8),
                            margin: const EdgeInsets.symmetric(vertical: 4),
                            decoration: BoxDecoration(
                              color: Colors.black87,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: SelectableText(
                              part["code"]!,
                              style: const TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 14,
                                color: Colors.greenAccent,
                              ),
                            ),
                          );
                        } else {
                          return SelectableText(
                            part["text"]!,
                            style: TextStyle(
                              color: isMyMessage ? Colors.white : Colors.black87,
                              fontSize: 16,
                            ),
                          );
                        }
                      }),
                      Align(
                        alignment: Alignment.bottomRight,
                        child: Padding(
                          padding: const EdgeInsets.only(top: 2),
                          child: Text(
                            formattedTime,
                            style: TextStyle(
                              color: isMyMessage ? Colors.white70 : Colors.black54,
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
          ),
        ),
      ),
    );
  }
}
