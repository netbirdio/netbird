package wsnhooyr

import (
	"context"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

func Dial(address string) (net.Conn, error) {

	hostName, _, err := net.SplitHostPort(address)

	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		log.Errorf("failed to resolve address of Relay server: %s", address)
		return nil, err
	}

	url := fmt.Sprintf("ws://%s:%d"+addr.IP.String(), addr.Port)
	opts := &websocket.DialOptions{
		Host: hostName,
	}

	wsConn, _, err := websocket.Dial(context.Background(), url, opts)
	if err != nil {
		return nil, err
	}

	conn := NewConn(wsConn, addr)

	return conn, nil
}
