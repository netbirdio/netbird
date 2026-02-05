//go:build js

package client

import (
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

func (c *Client) getDialers() []dialer.DialeFn {
	// JS/WASM build only uses WebSocket transport
	// Note: Client certificates (mTLS) are not supported in WASM builds
	// as the browser controls TLS configuration
	return []dialer.DialeFn{ws.Dialer{}}
}
