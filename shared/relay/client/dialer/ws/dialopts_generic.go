//go:build !js

package ws

import "github.com/coder/websocket"

func createDialOptions() *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(),
	}
}
