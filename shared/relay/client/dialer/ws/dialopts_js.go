//go:build js

package ws

import "github.com/coder/websocket"

func createDialOptions() *websocket.DialOptions {
	// WASM version doesn't support HTTPClient
	return &websocket.DialOptions{}
}
