package ws

const (
	Network = "ws"
)

type WebsocketAddr struct {
	addr string
}

func (a WebsocketAddr) Network() string {
	return Network
}

func (a WebsocketAddr) String() string {
	return a.addr
}
