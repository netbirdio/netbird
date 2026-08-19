package tcp

import (
	"fmt"
	"net"

	"github.com/pires/go-proxyproto"
)

// writeProxyProtoV2 sends a PROXY protocol v2 header to the backend connection,
// conveying the real client address.
func writeProxyProtoV2(client, backend net.Conn) error {
	tp := proxyproto.TCPv4
	if addr, ok := client.RemoteAddr().(*net.TCPAddr); ok && addr.IP.To4() == nil {
		tp = proxyproto.TCPv6
	}

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: tp,
		SourceAddr:        client.RemoteAddr(),
		DestinationAddr:   client.LocalAddr(),
	}
	if _, err := header.WriteTo(backend); err != nil {
		return fmt.Errorf("write PROXY protocol v2 header: %w", err)
	}
	return nil
}
