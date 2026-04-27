//go:build js

package ws

import (
	"crypto/tls"

	"github.com/coder/websocket"
)

func createDialOptions(_ *tls.Certificate) *websocket.DialOptions {
	// WASM version doesn't support HTTPClient or custom TLS config
	// The browser controls all TLS/certificate handling, so clientCert is ignored
	return &websocket.DialOptions{}
}
