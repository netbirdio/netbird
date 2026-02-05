//go:build !js

package ws

import (
	"crypto/tls"

	"github.com/coder/websocket"
)

func createDialOptions(clientCert *tls.Certificate) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(clientCert),
	}
}
