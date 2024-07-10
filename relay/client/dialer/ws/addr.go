package ws

type WebsocketAddr struct {
}

func (a WebsocketAddr) Network() string {
	return "websocket"
}

func (a WebsocketAddr) String() string {
	return "websocket/unknown-addr"
}
