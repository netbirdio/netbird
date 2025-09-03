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
	/*
		RedirectAs resume the forwarding the packages from relayed connection to WireGuard interface if it was paused
		and rewrite the src address	to the endpoint address.
		With this logic can avoid the package loss from relayed connections.
	*/
	RedirectAs(endpoint *net.UDPAddr)
	CloseConn() error
	SetDisconnectListener(disconnected func())
}
