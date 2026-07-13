//go:build !js

package client

import (
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/quic"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

// getDialers returns the ordered dialers for connecting to the relay server. It
// applies the datagram fallback generically: if this server recently rejected a
// datagram-sized transport, those dialers are dropped, leaving the rest.
func (c *Client) getDialers(mode TransportMode) []dialer.DialeFn {
	dialers := c.baseDialers(mode)

	if c.transportFallback != nil && c.transportFallback.avoidDatagramSized(c.connectionURL) {
		if filtered := nonDatagramSized(dialers); len(filtered) > 0 {
			c.log.Infof("relay recently rejected a datagram-sized transport, avoiding it")
			return filtered
		}
	}
	return dialers
}

// baseDialers returns the ordered dialers for the mode, before any datagram
// fallback filtering. For racing modes (auto) the order is irrelevant; for
// prefer modes the first entry is tried before falling back to the second.
func (c *Client) baseDialers(mode TransportMode) []dialer.DialeFn {
	switch mode {
	case TransportModeWS:
		c.log.Infof("%s=ws, using WebSocket transport", EnvRelayTransport)
		return []dialer.DialeFn{ws.Dialer{}}
	case TransportModeQUIC:
		c.log.Infof("%s=quic, using QUIC transport", EnvRelayTransport)
		return []dialer.DialeFn{quic.Dialer{}}
	}

	all := []dialer.DialeFn{quic.Dialer{}, ws.Dialer{}}
	if mode == TransportModePreferWS {
		all = []dialer.DialeFn{ws.Dialer{}, quic.Dialer{}}
	}

	if c.mtu > 0 && c.mtu > iface.DefaultMTU {
		c.log.Infof("MTU %d exceeds default (%d), avoiding datagram-sized transports", c.mtu, iface.DefaultMTU)
		return nonDatagramSized(all)
	}
	return all
}
