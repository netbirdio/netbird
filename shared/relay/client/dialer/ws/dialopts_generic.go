//go:build !js

package ws

import (
	"net"

	"github.com/coder/websocket"
)

func createDialOptions(serverName string, underlyingOut *net.Conn) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(serverName, underlyingOut),
	}
}
