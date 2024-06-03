package wsnhooyr

import (
	"context"
	"fmt"
	"net"

	"nhooyr.io/websocket"
)

func Dial(address string) (net.Conn, error) {

	addr := fmt.Sprintf("ws://" + address)
	wsConn, _, err := websocket.Dial(context.Background(), addr, nil)
	if err != nil {
		return nil, err
	}

	conn := NewConn(wsConn)

	return conn, nil
}
