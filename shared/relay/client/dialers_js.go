//go:build js

package client

import (
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/wt"
)

// getDialers returns the dialers used by the WASM/browser relay client.
//
// WebTransport is tried alongside WebSocket via the race dialer: whichever
// handshake completes first wins. WT loses fast against a relay that doesn't
// speak h3 (TLS no_application_protocol within one RTT), so the fallback to
// WS is cheap. The WASM client never uses raw QUIC — browsers don't expose
// UDP sockets.
func (c *Client) getDialers() []dialer.DialeFn {
	return []dialer.DialeFn{wt.Dialer{}, ws.Dialer{}}
}
