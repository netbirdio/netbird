package ws

import (
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

func Dial(address string) (net.Conn, error) {
	addr := fmt.Sprintf("ws://" + address)
	wsDialer := websocket.Dialer{
		HandshakeTimeout: 3 * time.Second,
	}
	wsConn, _, err := wsDialer.Dial(addr, nil)
	if err != nil {
		return nil, err
	}
	conn := NewConn(wsConn)
	return conn, nil
}
