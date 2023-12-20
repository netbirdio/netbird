package bind

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/pion/ice/v3"
	"github.com/pion/logging"
	"github.com/pion/stun/v2"
	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
	log "github.com/sirupsen/logrus"
)

/*
 Most of this code was copied from https://github.com/pion/ice and modified to fulfill NetBird's requirements
*/

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
	Net             transport.Net
	InterfaceFilter func(interfaceName string) bool
}

func localInterfaces(n transport.Net, interfaceFilter func(string) bool, ipFilter func(net.IP) bool, networkTypes []ice.NetworkType, includeLoopback bool) ([]net.IP, error) { //nolint:gocognit
	ips := []net.IP{}
	ifaces, err := n.Interfaces()
	if err != nil {
		return ips, err
	}

	var IPv4Requested, IPv6Requested bool
	for _, typ := range networkTypes {
		if typ.IsIPv4() {
			IPv4Requested = true
		}

		if typ.IsIPv6() {
			IPv6Requested = true
		}
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if (iface.Flags&net.FlagLoopback != 0) && !includeLoopback {
			continue // loopback interface
		}

		if interfaceFilter != nil && !interfaceFilter(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch addr := addr.(type) {
			case *net.IPNet:
				ip = addr.IP
			case *net.IPAddr:
				ip = addr.IP
			}
			if ip == nil || (ip.IsLoopback() && !includeLoopback) {
				continue
			}

			if ipv4 := ip.To4(); ipv4 == nil {
				if !IPv6Requested {
					continue
				} else if !isSupportedIPv6(ip) {
					continue
				}
			} else if !IPv4Requested {
				continue
			}

			if ipFilter != nil && !ipFilter(ip) {
				continue
			}

			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// The conditions of invalidation written below are defined in
// https://tools.ietf.org/html/rfc8445#section-5.1.1.1
func isSupportedIPv6(ip net.IP) bool {
	if len(ip) != net.IPv6len ||
		isZeros(ip[0:12]) || // !(IPv4-compatible IPv6)
		ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 || // !(IPv6 site-local unicast)
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func isZeros(ip net.IP) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return true
}

// NewUDPMuxDefault creates an implementation of UDPMux
func NewUDPMuxDefault(params UDPMuxParams) *UDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}

	var localAddrsForUnspecified []net.Addr
	if addr, ok := params.UDPConn.LocalAddr().(*net.UDPAddr); !ok {
		params.Logger.Errorf("LocalAddr is not a net.UDPAddr, got %T", params.UDPConn.LocalAddr())
	} else if ok && addr.IP.IsUnspecified() {
		// For unspecified addresses, the correct behavior is to return errListenUnspecified, but
		// it will break the applications that are already using unspecified UDP connection
		// with UDPMuxDefault, so print a warn log and create a local address list for mux.
		params.Logger.Warn("UDPMuxDefault should not listening on unspecified address, use NewMultiUDPMuxFromPort instead")
		var networks []ice.NetworkType
		switch {
		case addr.IP.To4() != nil:
			networks = []ice.NetworkType{ice.NetworkTypeUDP4}

		case addr.IP.To16() != nil:
			networks = []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}

		default:
			params.Logger.Errorf("LocalAddr expected IPV4 or IPV6, got %T", params.UDPConn.LocalAddr())
		}
		if len(networks) > 0 {
			if params.Net == nil {
				var err error
				if params.Net, err = stdnet.NewNet(); err != nil {
					params.Logger.Errorf("failed to get create network: %v", err)
				}
			}

			ips, err := localInterfaces(params.Net, params.InterfaceFilter, nil, networks, true)
			if err == nil {
				for _, ip := range ips {
					localAddrsForUnspecified = append(localAddrsForUnspecified, &net.UDPAddr{IP: ip, Port: addr.Port})
				}
			} else {
				params.Logger.Errorf("failed to get local interfaces for unspecified addr: %v", err)
			}
		}
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
		localAddrsForUnspecified: localAddrsForUnspecified,
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
	// don't check addr for mux using unspecified address
	if len(m.localAddrsForUnspecified) == 0 && m.params.UDPConn.LocalAddr().String() != addr.String() {
		return nil, fmt.Errorf("invalid address %s", addr.String())
	}

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

// HandleSTUNMessage handles STUN packets and forwards them to underlying pion/ice library
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
		destinationConnList = append(destinationConnList, storedConns...)
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
