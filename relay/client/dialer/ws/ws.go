package ws

import (
	"fmt"
	"net"

	"github.com/gorilla/websocket"
)

func Dial(address string) (net.Conn, error) {
	addr := fmt.Sprintf("ws://" + address)
	wsConn, _, err := websocket.DefaultDialer.Dial(addr, nil)
	if err != nil {
		return nil, err
	}
	conn := NewConn(wsConn)
	return conn, nil
}
