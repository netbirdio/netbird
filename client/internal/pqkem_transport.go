package internal

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/pqkem"
)

// DefaultPort is the preferred UDP port for the ML-KEM data-path service, bound on
// the WG overlay IP. Since each client owns a distinct overlay IP, this port is
// almost always free, so it need not be announced (peers assume it). A peer only
// announces Body.mlkemPort when a collision forced it onto a different port.
const DefaultPort = 51833

// pqTransport is the ML-KEM data-path transport: a dedicated UDP socket bound on the
// WireGuard overlay IP. Rekey messages travel through the tunnel to each peer's
// overlay IP and announced pqkem port. It implements pqkem.Transport and feeds
// inbound datagrams to the manager (set via setManager after construction, since the
// manager is built with this transport).
type pqTransport struct {
	conn *net.UDPConn
	port int

	mu     sync.RWMutex
	mgr    *pqkem.Manager
	peers  map[string]*net.UDPAddr // remoteID (WG pubkey) -> overlay UDP addr to send to
	byAddr map[string]string       // source addr string -> remoteID (inbound dispatch)
}

// newPQTransport binds a UDP socket on the WG overlay IP, preferring DefaultPort and
// falling back to an OS-assigned ephemeral port if it is in use. It must be called
// after the WG interface is up so the overlay IP is assigned; when the bound port is
// not DefaultPort it is announced to peers via Body.mlkemPort.
func newPQTransport(overlayIP netip.Addr) (*pqTransport, error) {
	if !overlayIP.IsValid() {
		return nil, fmt.Errorf("invalid overlay IP for pqkem transport")
	}
	ip := net.IP(overlayIP.AsSlice())
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: DefaultPort})
	if err != nil {
		// Default port unavailable (rare on a dedicated overlay IP): fall back to an
		// ephemeral port, which will be announced to peers.
		log.Debugf("pqkem: default port %d unavailable on %s (%v), using an ephemeral port", DefaultPort, overlayIP, err)
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("bind pqkem udp on overlay %s: %w", overlayIP, err)
		}
	}
	return &pqTransport{
		conn:   conn,
		port:   conn.LocalAddr().(*net.UDPAddr).Port,
		peers:  make(map[string]*net.UDPAddr),
		byAddr: make(map[string]string),
	}, nil
}

// Port is the bound UDP port, announced to peers as Body.mlkemPort.
func (t *pqTransport) Port() int { return t.port }

func (t *pqTransport) setManager(m *pqkem.Manager) {
	t.mu.Lock()
	t.mgr = m
	t.mu.Unlock()
}

// AddPeer records where a peer's rekey messages are sent: its overlay IP and the
// pqkem port it announced. A zero port or invalid IP is ignored.
func (t *pqTransport) AddPeer(remoteID string, overlayIP netip.Addr, port int) {
	if !overlayIP.IsValid() || port <= 0 {
		return
	}
	addr := &net.UDPAddr{IP: net.IP(overlayIP.AsSlice()), Port: port}
	t.mu.Lock()
	if old, ok := t.peers[remoteID]; ok {
		delete(t.byAddr, old.String())
	}
	t.peers[remoteID] = addr
	t.byAddr[addr.String()] = remoteID
	t.mu.Unlock()
}

func (t *pqTransport) RemovePeer(remoteID string) {
	t.mu.Lock()
	if a, ok := t.peers[remoteID]; ok {
		delete(t.byAddr, a.String())
		delete(t.peers, remoteID)
	}
	t.mu.Unlock()
}

// SendDataPath implements pqkem.Transport.
func (t *pqTransport) SendDataPath(remoteID string, msg []byte) error {
	t.mu.RLock()
	addr := t.peers[remoteID]
	t.mu.RUnlock()
	if addr == nil {
		return fmt.Errorf("no data-path address for peer %s", remoteID)
	}
	_, err := t.conn.WriteToUDP(msg, addr)
	return err
}

// run is the receive loop: it maps each datagram's source overlay address to a peer
// and feeds it to the manager. Exits when the socket is closed.
func (t *pqTransport) run() {
	buf := make([]byte, 2048)
	for {
		n, src, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		t.mu.RLock()
		remoteID := t.byAddr[src.String()]
		mgr := t.mgr
		t.mu.RUnlock()
		if remoteID == "" || mgr == nil {
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		if err := mgr.OnDataPathMessage(remoteID, msg); err != nil {
			log.Debugf("pqkem: inbound from %s: %v", remoteID, err)
		}
	}
}

func (t *pqTransport) Close() error { return t.conn.Close() }
