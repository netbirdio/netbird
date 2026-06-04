//go:build !js

package client

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/quic"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

// getDialers returns the ordered list of dialers for connecting to the relay
// server. For racing modes (auto) the order is irrelevant; for prefer modes the
// first entry is tried before falling back to the second.
func (c *Client) getDialers(mode TransportMode) []dialer.DialeFn {
	switch mode {
	case TransportModeWS:
		c.log.Infof("%s=ws, using WebSocket transport", EnvRelayTransport)
		return []dialer.DialeFn{ws.Dialer{}}
	case TransportModeQUIC:
		c.log.Infof("%s=quic, using QUIC transport", EnvRelayTransport)
		return []dialer.DialeFn{quic.Dialer{}}
	}

	if c.mtu > 0 && c.mtu > iface.DefaultMTU {
		c.log.Infof("MTU %d exceeds default (%d), forcing WebSocket transport to avoid DATAGRAM frame size issues", c.mtu, iface.DefaultMTU)
		return []dialer.DialeFn{ws.Dialer{}}
	}

	if c.transportFallback != nil && c.transportFallback.preferWS(c.connectionURL) {
		c.log.Infof("relay recently rejected QUIC datagrams, using WebSocket transport")
		return []dialer.DialeFn{ws.Dialer{}}
	}

	if mode == TransportModePreferWS {
		return []dialer.DialeFn{ws.Dialer{}, quic.Dialer{}}
	}
	return []dialer.DialeFn{quic.Dialer{}, ws.Dialer{}}
}
