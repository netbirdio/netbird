package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/stun"
)

const receiveMTU = 8192

// UDPMux allows multiple connections to go over a single UDP port
type UDPMux interface {
	io.Closer
	GetConn(ufrag string) (net.PacketConn, error)
	RemoveConnByUfrag(ufrag string)
}

// UDPMuxDefault is an implementation of the interface
type UDPMuxDefault struct {
	params UDPMuxParams

	closedChan chan struct{}
	closeOnce  sync.Once

	// conns is a map of all udpMuxedConn indexed by ufrag|network|candidateType
	conns map[string]*udpMuxedConn

	addressMapMu sync.RWMutex
	addressMap   map[string][]*udpMuxedConn

	// buffer pool to recycle buffers for net.UDPAddr encodes/decodes
	pool *sync.Pool

	mu sync.Mutex
}

const maxAddrSize = 512

// UDPMuxParams are parameters for UDPMux.
type UDPMuxParams struct {
	Logger  logging.LeveledLogger
	UDPConn net.PacketConn
}

// NewUDPMuxDefault creates an implementation of UDPMux
func NewUDPMuxDefault(params UDPMuxParams) *UDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}

	return &UDPMuxDefault{
		addressMap: map[string][]*udpMuxedConn{},
		params:     params,
		conns:      make(map[string]*udpMuxedConn),
		closedChan: make(chan struct{}, 1),
		pool: &sync.Pool{
			New: func() interface{} {
				// big enough buffer to fit both packet and address
				return newBufferHolder(receiveMTU + maxAddrSize)
			},
		},
	}
}

func (m *UDPMuxDefault) Type() string {
	return "HOST"
}

func (m *UDPMuxDefault) HandleSTUNMessage(msg *stun.Message, addr net.Addr) error {

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("underlying PacketConn did not return a UDPAddr")
	}

	// If we have already seen this address dispatch to the appropriate destination
	m.addressMapMu.Lock()
	var destinationConnList []*udpMuxedConn
	if storedConns, ok := m.addressMap[addr.String()]; ok {
		for _, conn := range storedConns {
			destinationConnList = append(destinationConnList, conn)
		}
	}
	m.addressMapMu.Unlock()

	// This block is needed to discover Peer Reflexive Candidates for which we don't know the Endpoint upfront.
	// However, we can take a username attribute from the STUN message which contains ufrag.
	// We can use ufrag to identify the destination conn to route packet to.

	attr, stunAttrErr := msg.Get(stun.AttrUsername)
	if stunAttrErr == nil {
		ufrag := strings.Split(string(attr), ":")[0]

		m.mu.Lock()
		if destinationConn, ok := m.conns[ufrag]; ok {
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

	for _, conn := range destinationConnList {
		if err := conn.writePacket(msg.Raw, udpAddr); err != nil {
			log.Errorf("could not write packet: %v", err)
		}
	}

	return nil
}

// LocalAddr returns the listening address of this UDPMuxDefault
func (m *UDPMuxDefault) LocalAddr() net.Addr {
	return m.params.UDPConn.LocalAddr()
}

// GetConn returns a PacketConn given the connection's ufrag and network
// creates the connection if an existing one can't be found
func (m *UDPMuxDefault) GetConn(ufrag string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Debugf("ICE %s: getting muxed connection for %s", m.Type(), ufrag)

	if m.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	if c, ok := m.conns[ufrag]; ok {
		return c, nil
	}

	c := m.createMuxedConn(ufrag)
	go func() {
		<-c.CloseChannel()
		m.removeConn(ufrag)
	}()
	m.conns[ufrag] = c
	return c, nil
}

// RemoveConnByUfrag stops and removes the muxed packet connection
func (m *UDPMuxDefault) RemoveConnByUfrag(ufrag string) {
	m.mu.Lock()
	removedConns := make([]*udpMuxedConn, 0)
	for key := range m.conns {
		if key != ufrag {
			continue
		}

		c := m.conns[key]
		delete(m.conns, key)
		if c != nil {
			removedConns = append(removedConns, c)
		}
	}
	// keep lock section small to avoid deadlock with conn lock
	m.mu.Unlock()

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	for _, c := range removedConns {
		addresses := c.getAddresses()
		for _, addr := range addresses {
			delete(m.addressMap, addr)
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

		for _, c := range m.conns {
			_ = c.Close()
		}
		m.conns = make(map[string]*udpMuxedConn)
		close(m.closedChan)
	})
	return err
}

func (m *UDPMuxDefault) removeConn(key string) {
	m.mu.Lock()
	c := m.conns[key]
	delete(m.conns, key)
	// keep lock section small to avoid deadlock with conn lock
	m.mu.Unlock()

	if c == nil {
		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	addresses := c.getAddresses()
	for _, addr := range addresses {
		if connList, ok := m.addressMap[addr]; ok {
			var newList []*udpMuxedConn
			for _, conn := range connList {
				if conn.params.Key != key {
					newList = append(newList, conn)
				}
			}
			m.addressMap[addr] = newList
		}
	}
}

func (m *UDPMuxDefault) writeTo(buf []byte, raddr net.Addr) (n int, err error) {
	return m.params.UDPConn.WriteTo(buf, raddr)
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
	log.Debugf("ICE: created muxed connection %s for %s", c.LocalAddr().String(), key)
	return c
}

type bufferHolder struct {
	buffer []byte
}

func newBufferHolder(size int) *bufferHolder {
	return &bufferHolder{
		buffer: make([]byte, size),
	}
}
