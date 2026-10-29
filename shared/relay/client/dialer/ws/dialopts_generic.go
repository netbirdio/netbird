//go:build !js

package ws

import (
	"net"

	"github.com/coder/websocket"
)

func createDialOptions(serverName, host string, underlyingOut *net.Conn) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(serverName, underlyingOut),
		Host:       host,
	}
}
