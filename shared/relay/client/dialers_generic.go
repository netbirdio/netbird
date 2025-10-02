//go:build !js

package client

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/quic"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

// getDialers returns the list of dialers to use for connecting to the relay server.
func (c *Client) getDialers() []dialer.DialeFn {
	if c.mtu > 0 && c.mtu > iface.DefaultMTU {
		c.log.Infof("MTU %d exceeds default (%d), forcing WebSocket transport to avoid DATAGRAM frame size issues", c.mtu, iface.DefaultMTU)
		return []dialer.DialeFn{ws.Dialer{}}
	}
	return []dialer.DialeFn{quic.Dialer{}, ws.Dialer{}}
}
