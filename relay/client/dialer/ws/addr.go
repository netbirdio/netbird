package ws

type WebsocketAddr struct {
	addr string
}

func (a WebsocketAddr) Network() string {
	return "websocket"
}

func (a WebsocketAddr) String() string {
	return a.addr
}
