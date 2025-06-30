import 'package:socket_io_client/socket_io_client.dart' as IO;

const _socketioBackendUrl = "http://mylb-1629095195.us-east-1.elb.amazonaws.com:5001";
// const _socketioBackendUrl = "http://192.168.0.104:5001";

IO.Socket connectToSocket(userId) {
  return IO.io(_socketioBackendUrl, IO.OptionBuilder()
  .setTransports(['websocket'])
  .disableAutoConnect()
  .setQuery({'user_id': userId})
  .build());
}
