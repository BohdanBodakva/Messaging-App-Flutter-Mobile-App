import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:messaging_app/handlers/messages.dart';
import 'package:messaging_app/models/chat.dart';
import 'package:messaging_app/models/user.dart';
import 'package:messaging_app/pages/chat_area.dart';
import 'package:messaging_app/providers/language_provider.dart';
import 'package:provider/provider.dart';
import 'package:socket_io_client/socket_io_client.dart';

class NewGroupPage extends StatefulWidget {
  final User? currentUser;
  final Function setCurrentUser;
  final bool isEditing;
  final Chat group;
  final Function openGroupChat;
  final Socket socket;

  const NewGroupPage({super.key, required this.socket, required this.currentUser, required this.setCurrentUser, required this.isEditing, required this.group, required this.openGroupChat});

  @override
  NewGroupPageState createState() => NewGroupPageState();
}

class NewGroupPageState extends State<NewGroupPage> {
  bool isGroupNameValid = true;

  // File? _groupImage;
  final _picker = ImagePicker();
  TextEditingController _groupNameController = TextEditingController();
  final TextEditingController _searchController = TextEditingController();

  List<User> _foundUsers = [];
  List<User> _selectedUsers = [];

  List<User> _selectedUsersCopy = [];

  late final bool isAdmin;

  @override
  void initState() {
    super.initState();

    setState(() {
      isGroupNameValid = true;
    });

    isAdmin = widget.group.adminId == widget.currentUser!.id;

    if (widget.isEditing == true) {
      _groupNameController = TextEditingController(text: widget.group.name ?? "");

      setState(() {
        _selectedUsers = widget.group.users!;
      });

      setState(() {
        _selectedUsersCopy = [..._selectedUsers];
      });
    }

    if (!isAdmin && !widget.isEditing) {
      _selectedUsers = [widget.currentUser!.deepCopy()];
    }

    widget.socket.on("search_users_for_group", (data) {
      if ((isAdmin && widget.isEditing) || (!isAdmin && !widget.isEditing)) {
        List<User> searchedUsers = (data["users"] as List).map((u) => User.fromJson(u)).toList();
      
        List<User> filteredList = searchedUsers.where(
          (u) => u.id != widget.currentUser!.id && 
          !_selectedUsers.map((u1) => u1.id
        ).toList().contains(u.id)).toList();

        setState(() {
          _foundUsers = filteredList;
        });
      }
      
    });

    widget.socket.on("change_group_info", (data) {
      Chat group = Chat.fromJson(data["updated_group"]);

      if (group.id == widget.group.id) {
        final groupUsersIds = group.users!.map((u) => u.id).toList();

        if (group.adminId == widget.currentUser!.id) {
          widget.socket.emit("load_user", {"user_id": widget.currentUser!.id});

          showSuccessToast(
            context, 
            Provider.of<LanguageProvider>(context, listen: false).localizedStrings["userInfoChangedSuccessfully"] ?? "Info was changed successfully"
          );
        } else {
          if (!groupUsersIds.contains(widget.currentUser!.id)) {
            Navigator.pop(context);
            Navigator.pop(context);
          }
        }
      }
    });

    widget.socket.on("leave_group", (data) {
      final userId = data["user_id"];
      final chatId = data["chat_id"];

      if (chatId != widget.group.id) {
        return;
      }

      widget.socket.emit("load_user_chats", {
        "user_id": widget.currentUser!.id
      });

      if (userId == widget.currentUser!.id) {
        widget.socket.emit("leave_room", {"room": chatId});

        Navigator.pop(context);

        showSuccessToast(
          context, 
          Provider.of<LanguageProvider>(context, listen: false).localizedStrings["leftFromGroup"] ?? "You have left from group"
        );
      }
    });

    widget.socket.on("delete_chat_from_chat_info", (data) {
      if (isAdmin == true) {
        final chatId = data["chat_id"];

        if (chatId != widget.group.id) {
          return;
        }

        showSuccessToast(
          context, 
          Provider.of<LanguageProvider>(context, listen: false).localizedStrings["groupDeleted"] ?? "Group was deleted"
        );
      }

      Navigator.pop(context);
    });

    widget.socket.on("create_group", (data) {
      final currentUserId = data["current_user_id"];
      final users = (data["users"] as List).map((u) => User.fromJson(u)).toList();
      final userIds = users.map((u) => u.id).toList();
      final chat = Chat.fromJson(data["chat"]);

      if (currentUserId == widget.currentUser!.id) {
        widget.socket.emit("load_user_chats", {
          "user_id": widget.currentUser!.id
        });

        widget.socket.emit("join_room", {"room": chat.id});

        User user = widget.currentUser!.deepCopy();
        user.chats = [chat, ...user.chats!];

        widget.setCurrentUser(user);

        Chat? chatWithUser = widget.currentUser!.chats!.firstWhere(
          (c) => c.id == chat.id,
          orElse: () => null
        );

        Navigator.of(context, rootNavigator: true).push(
          PageRouteBuilder(
            pageBuilder: (context, animation, secondaryAnimation) => ChatPage(socket: widget.socket, chat: chatWithUser!, currentUser: widget.currentUser, setCurrentUser: widget.setCurrentUser),
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

        showSuccessToast(
          context, 
          Provider.of<LanguageProvider>(context, listen: false).localizedStrings["chatCreatedSuccessfully"] ?? "Chat was created successfully"
        );

      } else if (userIds.contains(widget.currentUser!.id)) {
        widget.socket.emit("join_room", {"room": chat.id});
        
        widget.socket.emit("load_user_chats", {
          "user_id": widget.currentUser!.id
        });
      }
    });
  }

  // Future<void> _pickGroupImage() async {
  //   final pickedFile = await _picker.pickImage(source: ImageSource.gallery);
  //   if (pickedFile != null) {
  //     setState(() {
  //       _groupImage = File(pickedFile.path);
  //     });
  //   }
  // }

  void _selectUser(User user) {
    setState(() {
      _selectedUsers = [..._selectedUsers, user];

      _foundUsers = _foundUsers.where((u) => u.id != user.id).toList();
    });
  }

  void _unselectUser(User user) {
    setState(() {
      _selectedUsers = _selectedUsers.where((u) => u.id != user.id).toList();
    });

    if (_searchController.text.isNotEmpty) {
      widget.socket.emit("search_users_for_group", {
        "username_value": _searchController.text
      });
    }
    
  }

  void _createGroup() {
    setState(() {
      isGroupNameValid = true;
    });

    final groupName = _groupNameController.text;
    if (groupName.isEmpty) {
      setState(() {
        isGroupNameValid = false;
      });
    } else {
      widget.socket.emit("create_chat", {
        "current_user_id": widget.currentUser!.id,
        "user_ids": _selectedUsers.map((u) => u.id).where((id) => id != widget.currentUser!.id).toList(),
        "is_group": true,
        "created_at": DateTime.now().toIso8601String(),
        "name": groupName,
        "chat_photo_link": null
      });

      Navigator.pop(context);
    }
  }

  void _deleteGroup() {
    if (widget.group.adminId == widget.currentUser!.id) {
      widget.socket.emit("delete_chat", {
        "chat_id": widget.group.id
      });
    }
  }

  void _leaveGroup() {
    widget.socket.emit("leave_group", {
      "user_id": widget.currentUser!.id,
      "chat_id": widget.group.id
    });
  }

  void searchUsers(String value) {
    if (value.isEmpty) {
      setState(() {
        _foundUsers = [];
      });
    } else {
      widget.socket.emit("search_users_for_group", {
        "username_value": value
      });
    }
  }

  void _saveGroupChanges() {
    final newGroupName = _groupNameController.text;
    final newSelectedUsersIdsSet = _selectedUsers.map((u) => u.id).toSet();
    final oldSelectedUsersIdsSet = _selectedUsersCopy.map((u) => u.id).toSet();

    if ((newGroupName != widget.group.name) || (newSelectedUsersIdsSet != oldSelectedUsersIdsSet)){
      if (newGroupName.isEmpty) {
          
      } else {
        widget.socket.emit("change_group_info", {
          "group_id": widget.group.id,
          "new_user_ids": newSelectedUsersIdsSet.toList(),
          "new_name": newGroupName,
          "new_chat_photo_link": null
        });
      }
    }
  }

  @override
  void dispose() {
    widget.socket.off("search_users_for_group");
    widget.socket.off("create_group");
    widget.socket.off("leave_chat");
    widget.socket.off("change_group_info");
    widget.socket.off("leave_group");
    widget.socket.off("delete_chat_from_chat_info");

    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    var languageProvider = Provider.of<LanguageProvider>(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(
          widget.isEditing == true ?
          languageProvider.localizedStrings['groupInfo'] ?? "Group Info" :
          languageProvider.localizedStrings['newGroup'] ?? "New Group"
        ),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        centerTitle: true,
        leading: IconButton(icon: const Icon(Icons.arrow_back), onPressed: () => Navigator.of(context, rootNavigator: true).pop()),
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            children: [
              GestureDetector(
                onTap: () { /* _pickGroupImage */ },
                child: const CircleAvatar(
                  radius: 50,
                  backgroundImage: AssetImage('assets/letter_images/g.png'),
                    // _groupImage != null ? 
                  //   (isAdmin == true ? FileImage(_groupImage!) as ImageProvider : const AssetImage('assets/letter_images/g.png')) : 
                ),
              ),
              const SizedBox(height: 10),
              _buildTextField(isAdmin, widget.isEditing, _groupNameController, languageProvider.localizedStrings['groupName'] ?? "Group Name"),
              Visibility(
                visible: !isGroupNameValid,
                child: Padding(
                  padding: const EdgeInsets.only(top: 5.0, left: 5.0),
                  child: Text(
                    languageProvider.localizedStrings['fieldCannotBeEmpty'] ?? 'The filed cannot be empty', 
                    style: const TextStyle(color: Colors.red, fontSize: 12),
                  ),
                ),
              ),
              const SizedBox(height: 20),
              if ((widget.isEditing && isAdmin) || 
                  (!widget.isEditing && !isAdmin)
                 )
                TextField(
                  controller: _searchController,
                  onChanged: (value) {searchUsers(value);},
                  decoration: InputDecoration(
                    labelText: languageProvider.localizedStrings['searchUsers'] ?? "Search Users",
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 15),
                    prefixIcon: const Icon(Icons.search),
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.clear, color: Colors.grey),
                      onPressed: () {
                        setState(() {
                          _foundUsers = [];
                        });
                        _searchController.clear();
                      },
                    ),
                  ),
                ),
              if (widget.isEditing && !isAdmin)
                Text(
                  "${languageProvider.localizedStrings["groupUsers"] ?? "Users"}:",
                  style: const TextStyle(
                    fontWeight: FontWeight.w300, 
                    fontSize: 24,
                  ),
                ),
              const SizedBox(height: 10),
              if (_foundUsers.isNotEmpty)
                Center(
                  child: Container(
                    width: MediaQuery.of(context).size.width * 0.75,
                    height: 80,
                    padding: const EdgeInsets.symmetric(horizontal: 10),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(8),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(0.1),
                          blurRadius: 4,
                          spreadRadius: 2,
                        ),
                      ],
                    ),
                    child: SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: _foundUsers.map((user) {
                          return GestureDetector(
                            onTap: () {_selectUser(user);},
                            child: Padding(
                              padding: const EdgeInsets.symmetric(horizontal: 5),
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  CircleAvatar(
                                    radius: 25,
                                    backgroundImage: user.profilePhotoLink != null && !user.profilePhotoLink!.contains("assets/letter_images")
                                      ? NetworkImage(user.profilePhotoLink!)  as ImageProvider<Object>
                                      : AssetImage(user.profilePhotoLink ?? "assets/letter_images/u.png") as ImageProvider<Object>,
                                  ),
                                  const SizedBox(height: 5),
                                  Text(
                                    user.username!,
                                    style: const TextStyle(fontSize: 12),
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ],
                              ),
                            ),
                          );
                        }).toList(),
                      ),
                    ),
                  ),
                ),
              _buildSelectedUsers(isAdmin, widget.isEditing),
              const SizedBox(height: 20),
              if (widget.isEditing && isAdmin)
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _saveGroupChanges,
                    child: Text(languageProvider.localizedStrings['save'] ?? "Save"),
                  ),
                ),
              if (widget.isEditing)
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _leaveGroup,
                    child: Text(languageProvider.localizedStrings['leaveGroup'] ?? "Leave Group"),
                  ),
                ),
              if (widget.isEditing && isAdmin)
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _deleteGroup,
                    child: Text(languageProvider.localizedStrings['deleteGroup'] ?? "Delete Group"),
                  ),
                ),
              if (!widget.isEditing)
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _createGroup,
                    child: Text(languageProvider.localizedStrings['createGroup'] ?? "Create Group"),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTextField(bool isAdmin, bool isEditing, TextEditingController controller, String label) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: TextField(
        controller: controller,
        readOnly: !((isAdmin && isEditing) ||(!isAdmin && !isEditing)),
        decoration: InputDecoration(
          labelText: label,
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
          contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 15),
        ),
      ),
    );
  }

  Widget _buildSelectedUsers(bool isAdmin, bool isEditing) {
    return Wrap(
      spacing: 8.0,
      children: _selectedUsers.map((user) {
        final isCurrentUser = widget.currentUser!.id == user.id;

        return Chip(
          avatar: CircleAvatar(
            backgroundImage: user.profilePhotoLink != null && !user.profilePhotoLink!.contains("assets/letter_images")
              ? NetworkImage(user.profilePhotoLink!)  as ImageProvider<Object>
              : AssetImage(user.profilePhotoLink ?? "assets/letter_images/u.png") as ImageProvider<Object>,
          ),
          label: Text(user.username!),
          deleteIcon: !isCurrentUser && ((isAdmin && isEditing) ||(!isAdmin && !isEditing)) ? const Icon(Icons.close, size: 16) : null,
          onDeleted: !isCurrentUser && ((isAdmin && isEditing) ||(!isAdmin && !isEditing)) ? () => _unselectUser(user) : null,
        );
      }).toList(),
    );
  }
}
