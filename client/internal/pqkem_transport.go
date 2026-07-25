package internal

import (
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
)

// DefaultPort is the preferred UDP port for the ML-KEM data-path service, bound on
// the WG overlay IP. Since each client owns a distinct overlay IP, this port is
// almost always free, so it need not be announced (peers assume it). A peer only
// announces Body.mlkemPort when a collision forced it onto a different port.
const DefaultPort = 51833

// pqTransport is the ML-KEM data-path transport: a dumb UDP socket bound on the WG
// overlay IP. It implements pqkem.Transport — the manager owns the remoteID<->endpoint
// routing and drives this socket's lifecycle (Run / Close).
type pqTransport struct {
	conn *net.UDPConn
	port int
}

// newPQTransport binds a UDP socket on the WG overlay IP, preferring DefaultPort and
// falling back to an OS-assigned ephemeral port if it is in use. Call it after the WG
// interface is up so the overlay IP is assigned; when the bound port is not
// DefaultPort it must be announced to peers via Body.mlkemPort.
func newPQTransport(overlayIP netip.Addr) (*pqTransport, error) {
	if !overlayIP.IsValid() {
		return nil, fmt.Errorf("invalid overlay IP for pqkem transport")
	}
	ip := net.IP(overlayIP.AsSlice())
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: DefaultPort})
	if err != nil {
		log.Debugf("pqkem: default port %d unavailable on %s (%v), using an ephemeral port", DefaultPort, overlayIP, err)
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("bind pqkem udp on overlay %s: %w", overlayIP, err)
		}
	}
	return &pqTransport{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).Port}, nil
}

// Send implements pqkem.Transport.
func (t *pqTransport) Send(endpoint netip.AddrPort, msg []byte) error {
	_, err := t.conn.WriteToUDPAddrPort(msg, endpoint)
	return err
}

// LocalPort implements pqkem.Transport.
func (t *pqTransport) LocalPort() int { return t.port }

// Run implements pqkem.Transport: the receive loop, delivering each datagram as
// (source endpoint, msg). Exits when the socket is closed.
func (t *pqTransport) Run(onInbound func(src netip.AddrPort, msg []byte)) {
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := t.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			onInbound(src, msg)
		}
	}()
}

// Close implements pqkem.Transport.
func (t *pqTransport) Close() error { return t.conn.Close() }
