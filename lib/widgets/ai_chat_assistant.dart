import 'package:flutter/material.dart';
import 'package:socket_io_client/socket_io_client.dart';

class CounterPopup extends StatefulWidget {
  BuildContext oldContext;
  Function closeAIAssistantWindow;
  Socket socket;
  int? chatId;

  CounterPopup({required this.chatId, required this.socket, required this.oldContext, required this.closeAIAssistantWindow});

  @override
  _CounterPopupState createState() => _CounterPopupState();
}

class _CounterPopupState extends State<CounterPopup> {
  String responseText = "";

  int counter = 30;
  TextEditingController textController = TextEditingController();

  @override
  void initState() {
    super.initState();

    widget.socket.on("chat_summary", (data) {
      final response = data["response_text"];
      
      setState(() {
        responseText = response;
      });
    });
  }

  @override
  void dispose() {
    widget.socket.off("chat_summary");

    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    context = widget.oldContext;

    double wordCount = textController.text.split(RegExp(r'\s+')).length.toDouble();
    double progress = (wordCount / 20).clamp(0.0, 1.0);

    return Center(
      child: Container(
        width: MediaQuery.of(context).size.width * 0.7,
        height: MediaQuery.of(context).size.height * 0.5,
        padding: EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(12),
          boxShadow: [BoxShadow(color: Colors.black26, blurRadius: 8)],
        ),
        child: Stack(
          children: [
            Column(
              mainAxisAlignment: MainAxisAlignment.start,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'AI Assistant',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                  textAlign: TextAlign.center,
                ),
                SizedBox(height: 10),

                Text("Value: $counter", style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    IconButton(icon: Icon(Icons.remove), onPressed: () => setState(() => counter = (counter > 0) ? counter - 10 : 0)),
                    IconButton(icon: Icon(Icons.add), onPressed: () => setState(() => counter = (counter < 500) ? counter + 10 : 500)),
                  ],
                ),
                SizedBox(height: 10),

                TextField(
                  readOnly: true,
                  maxLines: 5,
                  decoration: InputDecoration(
                    border: OutlineInputBorder(),
                    hintText: responseText,
                  ),
                  controller: TextEditingController(text: responseText),
                  onChanged: (text) => setState(() {}),
                ),
                SizedBox(height: 10),
                ElevatedButton(
                  onPressed: () {
                    widget.socket.emit("ai_chat", {
                      "summarize_chat_history": true,
                      "message_count": counter,
                      "chat_id": widget.chatId
                    });
                  },
                  style: ElevatedButton.styleFrom(
                    padding: EdgeInsets.symmetric(vertical: 14),
                    textStyle: TextStyle(fontSize: 16),
                  ),
                  child: Text('Close Assistant'),
                ),
              ],
            ),
            Positioned(
              right: 0,
              top: 0,
              child: IconButton(
                icon: Icon(Icons.close),
                onPressed: () {
                  setState(() {
                    responseText = "";
                  });

                  widget.closeAIAssistantWindow();
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
