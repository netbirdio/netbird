package internal

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

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
	conn net.PacketConn
	port int
	wg   sync.WaitGroup
}

// newPQTransport binds a UDP socket on the WG overlay IP, preferring DefaultPort and
// falling back to an OS-assigned ephemeral port if it is in use. Call it after the WG
// interface is up so the overlay IP is assigned; when the bound port is not
// DefaultPort it must be announced to peers via Body.mlkemPort.
func newPQTransport(overlayIP netip.Addr) (*pqTransport, error) {
	if !overlayIP.IsValid() {
		return nil, fmt.Errorf("invalid overlay IP for pqkem transport")
	}
	// The WG overlay always carries an IPv4 address (v6 is additive, never standalone),
	// so the transport binds over IPv4. Unmap first so AsSlice() yields 4 bytes for an
	// IPv4-mapped IPv6 address (a hardcoded "udp4" would otherwise fail on its 16 bytes).
	overlayIP = overlayIP.Unmap()
	listen := func(port uint16) (net.PacketConn, error) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(overlayIP.AsSlice()), Port: int(port)})
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	conn, err := listen(DefaultPort)
	if err != nil {
		log.Debugf("pqkem: default port %d unavailable on %s (%v), using an ephemeral port", DefaultPort, overlayIP, err)
		conn, err = listen(0)
		if err != nil {
			return nil, fmt.Errorf("bind pqkem udp on overlay %s: %w", overlayIP, err)
		}
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("pqkem transport bound to a non-UDP address %s", conn.LocalAddr())
	}
	return &pqTransport{conn: conn, port: local.Port}, nil
}

// Send implements pqkem.Transport.
func (t *pqTransport) Send(endpoint netip.AddrPort, msg []byte) error {
	_, err := t.conn.WriteTo(msg, net.UDPAddrFromAddrPort(endpoint))
	return err
}

// LocalPort implements pqkem.Transport.
func (t *pqTransport) LocalPort() int { return t.port }

// Run implements pqkem.Transport: the receive loop, delivering each datagram as
// (source endpoint, msg). Exits when the socket is closed.
func (t *pqTransport) Run(onInbound func(src netip.AddrPort, msg []byte)) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		buf := make([]byte, 2048)
		for {
			n, addr, err := t.conn.ReadFrom(buf)
			if err != nil {
				return
			}
			src, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			ap := src.AddrPort()
			msg := make([]byte, n)
			copy(msg, buf[:n])
			onInbound(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), msg)
		}
	}()
}

// Close implements pqkem.Transport. It closes the socket (unblocking the read) and drains
// the receive loop, so no onInbound callback is still running when Close returns.
func (t *pqTransport) Close() error {
	err := t.conn.Close()
	t.wg.Wait()
	return err
}
