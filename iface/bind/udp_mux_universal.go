package bind

/*
 Most of this code was copied from https://github.com/pion/ice and modified to fulfill NetBird's requirements.
*/

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pion/logging"
	"github.com/pion/stun/v2"
	"github.com/pion/transport/v3"
)

// UniversalUDPMuxDefault handles STUN and TURN servers packets by wrapping the original UDPConn
// It then passes packets to the UDPMux that does the actual connection muxing.
type UniversalUDPMuxDefault struct {
	*UDPMuxDefault
	params UniversalUDPMuxParams

	// since we have a shared socket, for srflx candidates it makes sense to have a shared mapped address across all the agents
	// stun.XORMappedAddress indexed by the STUN server addr
	xorMappedMap map[string]*xorMapped
}

// UniversalUDPMuxParams are parameters for UniversalUDPMux server reflexive.
type UniversalUDPMuxParams struct {
	Logger                logging.LeveledLogger
	UDPConn               net.PacketConn
	XORMappedAddrCacheTTL time.Duration
	Net                   transport.Net
}

// NewUniversalUDPMuxDefault creates an implementation of UniversalUDPMux embedding UDPMux
func NewUniversalUDPMuxDefault(params UniversalUDPMuxParams) *UniversalUDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}
	if params.XORMappedAddrCacheTTL == 0 {
		params.XORMappedAddrCacheTTL = time.Second * 25
	}

	m := &UniversalUDPMuxDefault{
		params:       params,
		xorMappedMap: make(map[string]*xorMapped),
	}

	// wrap UDP connection, process server reflexive messages
	// before they are passed to the UDPMux connection handler (connWorker)
	m.params.UDPConn = &udpConn{
		PacketConn: params.UDPConn,
		mux:        m,
		logger:     params.Logger,
	}

	// embed UDPMux
	udpMuxParams := UDPMuxParams{
		Logger:  params.Logger,
		UDPConn: m.params.UDPConn,
		Net:     m.params.Net,
	}
	m.UDPMuxDefault = NewUDPMuxDefault(udpMuxParams)

	return m
}

// ReadFromConn reads from the m.params.UDPConn provided upon the creation. It expects STUN packets only, however, will
// just ignore other packets printing an warning message.
// It is a blocking method, consider running in a go routine.
func (m *UniversalUDPMuxDefault) ReadFromConn(ctx context.Context) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			log.Debugf("stopped reading from the UDPConn due to finished context")
			return
		default:
			n, a, err := m.params.UDPConn.ReadFrom(buf)
			if err != nil {
				log.Errorf("error while reading packet: %s", err)
				continue
			}
			msg := &stun.Message{
				Raw: append([]byte{}, buf[:n]...),
			}
			err = msg.Decode()
			if err != nil {
				log.Warnf("error while parsing STUN message. The packet doesn't seem to be a STUN packet: %s", err)
				continue
			}

			err = m.HandleSTUNMessage(msg, a)
			if err != nil {
				log.Errorf("error while handling STUn message: %s", err)
			}
		}
	}
}

// udpConn is a wrapper around UDPMux conn that overrides ReadFrom and handles STUN/TURN packets
type udpConn struct {
	net.PacketConn
	mux    *UniversalUDPMuxDefault
	logger logging.LeveledLogger
}

// GetSharedConn returns the shared udp conn
func (m *UniversalUDPMuxDefault) GetSharedConn() net.PacketConn {
	return m.params.UDPConn
}

// GetListenAddresses returns the listen addr of this UDP
func (m *UniversalUDPMuxDefault) GetListenAddresses() []net.Addr {
	return []net.Addr{m.LocalAddr()}
}

// GetRelayedAddr creates relayed connection to the given TURN service and returns the relayed addr.
// Not implemented yet.
func (m *UniversalUDPMuxDefault) GetRelayedAddr(turnAddr net.Addr, deadline time.Duration) (*net.Addr, error) {
	return nil, fmt.Errorf("not implemented yet")
}

// GetConnForURL add uniques to the muxed connection by concatenating ufrag and URL (e.g. STUN URL) to be able to support multiple STUN/TURN servers
// and return a unique connection per server.
func (m *UniversalUDPMuxDefault) GetConnForURL(ufrag string, url string, addr net.Addr) (net.PacketConn, error) {
	return m.UDPMuxDefault.GetConn(fmt.Sprintf("%s%s", ufrag, url), addr)
}

// HandleSTUNMessage discovers STUN packets that carry a XOR mapped address from a STUN server.
// All other STUN packets will be forwarded to the UDPMux
func (m *UniversalUDPMuxDefault) HandleSTUNMessage(msg *stun.Message, addr net.Addr) error {

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		// message about this err will be logged in the UDPMux
		return nil
	}

	if m.isXORMappedResponse(msg, udpAddr.String()) {
		err := m.handleXORMappedResponse(udpAddr, msg)
		if err != nil {
			log.Debugf("%s: %v", fmt.Errorf("failed to get XOR-MAPPED-ADDRESS response"), err)
			return nil
		}
		return nil
	}
	return m.UDPMuxDefault.HandleSTUNMessage(msg, addr)
}

// isXORMappedResponse indicates whether the message is a XORMappedAddress and is coming from the known STUN server.
func (m *UniversalUDPMuxDefault) isXORMappedResponse(msg *stun.Message, stunAddr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// check first if it is a STUN server address because remote peer can also send similar messages but as a BindingSuccess
	_, ok := m.xorMappedMap[stunAddr]
	_, err := msg.Get(stun.AttrXORMappedAddress)
	return err == nil && ok
}

// handleXORMappedResponse parses response from the STUN server, extracts XORMappedAddress attribute
// and set the mapped address for the server
func (m *UniversalUDPMuxDefault) handleXORMappedResponse(stunAddr *net.UDPAddr, msg *stun.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mappedAddr, ok := m.xorMappedMap[stunAddr.String()]
	if !ok {
		return fmt.Errorf("no XOR address mapping")
	}

	var addr stun.XORMappedAddress
	if err := addr.GetFrom(msg); err != nil {
		return err
	}

	m.xorMappedMap[stunAddr.String()] = mappedAddr
	mappedAddr.SetAddr(&addr)

	return nil
}

// GetXORMappedAddr returns *stun.XORMappedAddress if already present for a given STUN server.
// Makes a STUN binding request to discover mapped address otherwise.
// Blocks until the stun.XORMappedAddress has been discovered or deadline.
// Method is safe for concurrent use.
func (m *UniversalUDPMuxDefault) GetXORMappedAddr(serverAddr net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error) {
	m.mu.Lock()
	mappedAddr, ok := m.xorMappedMap[serverAddr.String()]
	// if we already have a mapping for this STUN server (address already received)
	// and if it is not too old we return it without making a new request to STUN server
	if ok {
		if mappedAddr.expired() {
			mappedAddr.closeWaiters()
			delete(m.xorMappedMap, serverAddr.String())
			ok = false
		} else if mappedAddr.pending() {
			ok = false
		}
	}
	m.mu.Unlock()
	if ok {
		return mappedAddr.addr, nil
	}

	// otherwise, make a STUN request to discover the address
	// or wait for already sent request to complete
	waitAddrReceived, err := m.sendSTUN(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", "failed to send STUN packet", err)
	}

	// block until response was handled by the connWorker routine and XORMappedAddress was updated
	select {
	case <-waitAddrReceived:
		// when channel closed, addr was obtained
		var addr *stun.XORMappedAddress
		m.mu.Lock()
		// A very odd case that mappedAddr is nil.
		// Can happen when the deadline property is larger than params.XORMappedAddrCacheTTL.
		// Or when we don't receive a response to our m.sendSTUN request (the response is handled asynchronously) and
		// the XORMapped expires meanwhile triggering a closure of the waitAddrReceived channel.
		// We protect the code from panic here.
		if mappedAddr, ok := m.xorMappedMap[serverAddr.String()]; ok {
			addr = mappedAddr.addr
		}
		m.mu.Unlock()
		if addr == nil {
			return nil, fmt.Errorf("no XOR address mapping")
		}
		return addr, nil
	case <-time.After(deadline):
		return nil, fmt.Errorf("timeout while waiting for XORMappedAddr")
	}
}

// sendSTUN sends a STUN request via UDP conn.
//
// The returned channel is closed when the STUN response has been received.
// Method is safe for concurrent use.
func (m *UniversalUDPMuxDefault) sendSTUN(serverAddr net.Addr) (chan struct{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// if record present in the map, we already sent a STUN request,
	// just wait when waitAddrReceived will be closed
	addrMap, ok := m.xorMappedMap[serverAddr.String()]
	if !ok {
		addrMap = &xorMapped{
			expiresAt:        time.Now().Add(m.params.XORMappedAddrCacheTTL),
			waitAddrReceived: make(chan struct{}),
		}
		m.xorMappedMap[serverAddr.String()] = addrMap
	}

	req, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return nil, err
	}

	if _, err = m.params.UDPConn.WriteTo(req.Raw, serverAddr); err != nil {
		return nil, err
	}

	return addrMap.waitAddrReceived, nil
}

type xorMapped struct {
	addr             *stun.XORMappedAddress
	waitAddrReceived chan struct{}
	expiresAt        time.Time
}

func (a *xorMapped) closeWaiters() {
	select {
	case <-a.waitAddrReceived:
		// notify was close, ok, that means we received duplicate response
		// just exit
		break
	default:
		// notify that twe have a new addr
		close(a.waitAddrReceived)
	}
}

func (a *xorMapped) pending() bool {
	return a.addr == nil
}

func (a *xorMapped) expired() bool {
	return a.expiresAt.Before(time.Now())
}

func (a *xorMapped) SetAddr(addr *stun.XORMappedAddress) {
	a.addr = addr
	a.closeWaiters()
}
