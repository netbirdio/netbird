package wgproxy

import (
	"context"
	"net"
)

// Proxy is a transfer layer between the relayed connection and the WireGuard
type Proxy interface {
	AddTurnConn(ctx context.Context, endpoint *net.UDPAddr, remoteConn net.Conn) error
	EndpointAddr() *net.UDPAddr // EndpointAddr returns the address of the WireGuard peer endpoint
	Work()                      // Work start or resume the proxy
	Pause()                     // Pause to forward the packages from remote connection to WireGuard. The opposite way still works.

	//RedirectAs forwards the packages from the relayed connection to the WireGuard interface
	//with the src address rewritten to the endpoint address, starting the proxy if needed and
	//resuming it if it was paused. Never delivers a packet with the relayed fake address —
	//WireGuard would roam to it.
	RedirectAs(endpoint *net.UDPAddr)
	CloseConn() error
	SetDisconnectListener(disconnected func())

	// InjectPacket writes a raw packet directly to the remote peer over the underlying transport,
	// bypassing WireGuard. Used to replay the captured lazyconn handshake initiation. Only the
	// kernel-mode proxies act on it; the userspace proxy is a no-op since reinjection is kernel-only.
	InjectPacket(b []byte) error
}
