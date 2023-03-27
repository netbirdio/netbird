package bind

import (
	"fmt"
	"github.com/pion/stun"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/transport/v2"
)

const receiveMTU = 8192

// UDPMuxDefault is an implementation of the interface
type UDPMuxDefault struct {
	params UDPMuxParams

	closedChan chan struct{}
	closeOnce  sync.Once

	// connsIPv4 and connsIPv6 are maps of all udpMuxedConn indexed by ufrag|network|candidateType
	connsIPv4, connsIPv6 map[string]*udpMuxedConn

	addressMapMu sync.RWMutex
	addressMap   map[string][]*udpMuxedConn

	// buffer pool to recycle buffers for net.UDPAddr encodes/decodes
	pool *sync.Pool

	mu sync.Mutex

	// for UDP connection listen at unspecified address
	localAddrsForUnspecified []net.Addr
}

const maxAddrSize = 512

// UDPMuxParams are parameters for UDPMux.
type UDPMuxParams struct {
	Logger  logging.LeveledLogger
	UDPConn net.PacketConn

	// Required for gathering local addresses
	// in case a un UDPConn is passed which does not
	// bind to a specific local address.
	Net transport.Net
}

// NewUDPMuxDefault creates an implementation of UDPMux
func NewUDPMuxDefault(params UDPMuxParams) *UDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}

	return &UDPMuxDefault{
		addressMap: map[string][]*udpMuxedConn{},
		params:     params,
		connsIPv4:  make(map[string]*udpMuxedConn),
		connsIPv6:  make(map[string]*udpMuxedConn),
		closedChan: make(chan struct{}, 1),
		pool: &sync.Pool{
			New: func() interface{} {
				// big enough buffer to fit both packet and address
				return newBufferHolder(receiveMTU + maxAddrSize)
			},
		},
		localAddrsForUnspecified: []net.Addr{},
	}
}

// LocalAddr returns the listening address of this UDPMuxDefault
func (m *UDPMuxDefault) LocalAddr() net.Addr {
	return m.params.UDPConn.LocalAddr()
}

// GetListenAddresses returns the list of addresses that this mux is listening on
func (m *UDPMuxDefault) GetListenAddresses() []net.Addr {
	if len(m.localAddrsForUnspecified) > 0 {
		return m.localAddrsForUnspecified
	}

	return []net.Addr{m.LocalAddr()}
}

// GetConn returns a PacketConn given the connection's ufrag and network address
// creates the connection if an existing one can't be found
func (m *UDPMuxDefault) GetConn(ufrag string, addr net.Addr) (net.PacketConn, error) {

	var isIPv6 bool
	if udpAddr, _ := addr.(*net.UDPAddr); udpAddr != nil && udpAddr.IP.To4() == nil {
		isIPv6 = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	if conn, ok := m.getConn(ufrag, isIPv6); ok {
		return conn, nil
	}

	c := m.createMuxedConn(ufrag)
	go func() {
		<-c.CloseChannel()
		m.RemoveConnByUfrag(ufrag)
	}()

	if isIPv6 {
		m.connsIPv6[ufrag] = c
	} else {
		m.connsIPv4[ufrag] = c
	}

	return c, nil
}

// RemoveConnByUfrag stops and removes the muxed packet connection
func (m *UDPMuxDefault) RemoveConnByUfrag(ufrag string) {
	removedConns := make([]*udpMuxedConn, 0, 2)

	// Keep lock section small to avoid deadlock with conn lock
	m.mu.Lock()
	if c, ok := m.connsIPv4[ufrag]; ok {
		delete(m.connsIPv4, ufrag)
		removedConns = append(removedConns, c)
	}
	if c, ok := m.connsIPv6[ufrag]; ok {
		delete(m.connsIPv6, ufrag)
		removedConns = append(removedConns, c)
	}
	m.mu.Unlock()

	if len(removedConns) == 0 {
		// No need to lock if no connection was found
		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	for _, c := range removedConns {
		addresses := c.getAddresses()
		for _, addr := range addresses {
			if connList, ok := m.addressMap[addr]; ok {
				var newList []*udpMuxedConn
				for _, conn := range connList {
					if conn.params.Key != ufrag {
						newList = append(newList, conn)
					}
				}
				m.addressMap[addr] = newList
			}
		}
	}
}

// IsClosed returns true if the mux had been closed
func (m *UDPMuxDefault) IsClosed() bool {
	select {
	case <-m.closedChan:
		return true
	default:
		return false
	}
}

// Close the mux, no further connections could be created
func (m *UDPMuxDefault) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, c := range m.connsIPv4 {
			_ = c.Close()
		}
		for _, c := range m.connsIPv6 {
			_ = c.Close()
		}

		m.connsIPv4 = make(map[string]*udpMuxedConn)
		m.connsIPv6 = make(map[string]*udpMuxedConn)

		close(m.closedChan)

		_ = m.params.UDPConn.Close()
	})
	return err
}

func (m *UDPMuxDefault) writeTo(buf []byte, rAddr net.Addr) (n int, err error) {
	return m.params.UDPConn.WriteTo(buf, rAddr)
}

func (m *UDPMuxDefault) registerConnForAddress(conn *udpMuxedConn, addr string) {
	if m.IsClosed() {
		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	existing, ok := m.addressMap[addr]
	if !ok {
		existing = []*udpMuxedConn{}
	}
	existing = append(existing, conn)
	m.addressMap[addr] = existing

	log.Debugf("ICE: registered %s for %s", addr, conn.params.Key)
}

func (m *UDPMuxDefault) createMuxedConn(key string) *udpMuxedConn {
	c := newUDPMuxedConn(&udpMuxedConnParams{
		Mux:       m,
		Key:       key,
		AddrPool:  m.pool,
		LocalAddr: m.LocalAddr(),
		Logger:    m.params.Logger,
	})
	return c
}

func (m *UDPMuxDefault) HandleSTUNMessage(msg *stun.Message, addr net.Addr) error {

	remoteAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("underlying PacketConn did not return a UDPAddr")
	}

	// If we have already seen this address dispatch to the appropriate destination
	// If you are using the same socket for the Host and SRFLX candidates, it might be that there are more than one
	// muxed connection - one for the SRFLX candidate and the other one for the HOST one.
	// We will then forward STUN packets to each of these connections.
	m.addressMapMu.Lock()
	var destinationConnList []*udpMuxedConn
	if storedConns, ok := m.addressMap[addr.String()]; ok {
		for _, conn := range storedConns {
			destinationConnList = append(destinationConnList, conn)
		}
	}
	m.addressMapMu.Unlock()

	var isIPv6 bool
	if udpAddr, _ := addr.(*net.UDPAddr); udpAddr != nil && udpAddr.IP.To4() == nil {
		isIPv6 = true
	}

	// This block is needed to discover Peer Reflexive Candidates for which we don't know the Endpoint upfront.
	// However, we can take a username attribute from the STUN message which contains ufrag.
	// We can use ufrag to identify the destination conn to route packet to.
	attr, stunAttrErr := msg.Get(stun.AttrUsername)
	if stunAttrErr == nil {
		ufrag := strings.Split(string(attr), ":")[0]

		m.mu.Lock()
		destinationConn := m.connsIPv4[ufrag]
		if isIPv6 {
			destinationConn = m.connsIPv6[ufrag]
		}

		if destinationConn != nil {
			exists := false
			for _, conn := range destinationConnList {
				if conn.params.Key == destinationConn.params.Key {
					exists = true
					break
				}
			}
			if !exists {
				destinationConnList = append(destinationConnList, destinationConn)
			}
		}
		m.mu.Unlock()
	}

	// Forward STUN packets to each destination connections even thought the STUN packet might not belong there.
	// It will be discarded by the further ICE candidate logic if so.
	for _, conn := range destinationConnList {
		if err := conn.writePacket(msg.Raw, remoteAddr); err != nil {
			log.Errorf("could not write packet: %v", err)
		}
	}

	return nil
}

func (m *UDPMuxDefault) getConn(ufrag string, isIPv6 bool) (val *udpMuxedConn, ok bool) {
	if isIPv6 {
		val, ok = m.connsIPv6[ufrag]
	} else {
		val, ok = m.connsIPv4[ufrag]
	}
	return
}

type bufferHolder struct {
	buf []byte
}

func newBufferHolder(size int) *bufferHolder {
	return &bufferHolder{
		buf: make([]byte, size),
	}
}
