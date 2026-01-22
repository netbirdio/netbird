//go:build !js

package bind

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"github.com/pion/stun/v3"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
	wgConn "golang.zx2c4.com/wireguard/conn"

	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type receiverCreator struct {
	iceBind *ICEBind
}

func (rc receiverCreator) CreateReceiverFn(pc wgConn.BatchReader, conn *net.UDPConn, rxOffload bool, msgPool *sync.Pool) wgConn.ReceiveFunc {
	return rc.iceBind.createReceiverFn(pc, conn, rxOffload, msgPool)
}

// ICEBind is a bind implementation with two main features:
// 1. filter out STUN messages and handle them
// 2. forward the received packets to the WireGuard interface from the relayed connection
//
// ICEBind.endpoints var is a map that stores the connection for each relayed peer. Fake address is just an IP address
// without port, in the format of 127.1.x.x where x.x is the last two octets of the peer address. We try to avoid to
// use the port because in the Send function the wgConn.Endpoint the port info is not exported.
type ICEBind struct {
	*wgConn.StdNetBind

	transportNet transport.Net
	filterFn     udpmux.FilterFn
	address      wgaddr.Address
	mtu          uint16

	endpoints   map[netip.Addr]net.Conn
	endpointsMu sync.Mutex
	recvChan    chan recvMessage
	// every time when Close() is called (i.e. BindUpdate()) we need to close exit from the receiveRelayed and create a
	// new closed channel. With the closedChanMu we can safely close the channel and create a new one
	closedChan       chan struct{}
	closedChanMu     sync.RWMutex // protect the closeChan recreation from reading from it.
	closed           bool
	activityRecorder *ActivityRecorder

	muUDPMux sync.Mutex
	udpMux   *udpmux.UniversalUDPMuxDefault
	ipv4Conn *net.UDPConn
	ipv6Conn *net.UDPConn
}

func NewICEBind(transportNet transport.Net, filterFn udpmux.FilterFn, address wgaddr.Address, mtu uint16) *ICEBind {
	b, _ := wgConn.NewStdNetBind().(*wgConn.StdNetBind)
	ib := &ICEBind{
		StdNetBind:       b,
		transportNet:     transportNet,
		filterFn:         filterFn,
		address:          address,
		mtu:              mtu,
		endpoints:        make(map[netip.Addr]net.Conn),
		recvChan:         make(chan recvMessage, 1),
		closedChan:       make(chan struct{}),
		closed:           true,
		activityRecorder: NewActivityRecorder(),
	}

	rc := receiverCreator{
		ib,
	}
	ib.StdNetBind = wgConn.NewStdNetBindWithReceiverCreator(rc)
	return ib
}

func (s *ICEBind) Open(uport uint16) ([]wgConn.ReceiveFunc, uint16, error) {
	s.closed = false
	s.closedChanMu.Lock()
	s.closedChan = make(chan struct{})
	s.closedChanMu.Unlock()
	fns, port, err := s.StdNetBind.Open(uport)
	if err != nil {
		return nil, 0, err
	}
	fns = append(fns, s.receiveRelayed)
	return fns, port, nil
}

func (s *ICEBind) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	close(s.closedChan)

	s.muUDPMux.Lock()
	s.ipv4Conn = nil
	s.ipv6Conn = nil
	s.udpMux = nil
	s.muUDPMux.Unlock()

	return s.StdNetBind.Close()
}

func (s *ICEBind) ActivityRecorder() *ActivityRecorder {
	return s.activityRecorder
}

// GetICEMux returns the ICE UDPMux that was created and used by ICEBind
func (s *ICEBind) GetICEMux() (*udpmux.UniversalUDPMuxDefault, error) {
	s.muUDPMux.Lock()
	defer s.muUDPMux.Unlock()
	if s.udpMux == nil {
		return nil, fmt.Errorf("ICEBind has not been initialized yet")
	}

	return s.udpMux, nil
}

func (b *ICEBind) SetEndpoint(fakeIP netip.Addr, conn net.Conn) {
	b.endpointsMu.Lock()
	b.endpoints[fakeIP] = conn
	b.endpointsMu.Unlock()
}

func (b *ICEBind) RemoveEndpoint(fakeIP netip.Addr) {
	b.endpointsMu.Lock()
	defer b.endpointsMu.Unlock()

	delete(b.endpoints, fakeIP)
}

func (b *ICEBind) ReceiveFromEndpoint(ctx context.Context, ep *Endpoint, buf []byte) {
	select {
	case <-b.closedChan:
		return
	case <-ctx.Done():
		return
	case b.recvChan <- recvMessage{ep, buf}:
	}
}

func (b *ICEBind) Send(bufs [][]byte, ep wgConn.Endpoint) error {
	b.endpointsMu.Lock()
	conn, ok := b.endpoints[ep.DstIP()]
	b.endpointsMu.Unlock()
	if !ok {
		return b.StdNetBind.Send(bufs, ep)
	}

	for _, buf := range bufs {
		if _, err := conn.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (s *ICEBind) createReceiverFn(pc wgConn.BatchReader, conn *net.UDPConn, rxOffload bool, msgsPool *sync.Pool) wgConn.ReceiveFunc {
	s.muUDPMux.Lock()
	defer s.muUDPMux.Unlock()

	// Detect IPv4 vs IPv6 from connection's local address
	if localAddr := conn.LocalAddr().(*net.UDPAddr); localAddr.IP.To4() != nil {
		s.ipv4Conn = conn
	} else {
		s.ipv6Conn = conn
	}
	s.createOrUpdateMux()

	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (n int, err error) {
		msgs := getMessages(msgsPool)
		for i := range bufs {
			(*msgs)[i].Buffers[0] = bufs[i]
			(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
		}
		defer putMessages(msgs, msgsPool)

		var numMsgs int
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			if rxOffload {
				readAt := len(*msgs) - (wgConn.IdealBatchSize / wgConn.UdpSegmentMaxDatagrams)
				//nolint:staticcheck
				_, err = pc.ReadBatch((*msgs)[readAt:], 0)
				if err != nil {
					return 0, err
				}
				numMsgs, err = wgConn.SplitCoalescedMessages(*msgs, readAt, wgConn.GetGSOSize)
				if err != nil {
					return 0, err
				}
			} else {
				numMsgs, err = pc.ReadBatch(*msgs, 0)
				if err != nil {
					return 0, err
				}
			}
		} else {
			msg := &(*msgs)[0]
			msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
			if err != nil {
				return 0, err
			}
			numMsgs = 1
		}

		for i := 0; i < numMsgs; i++ {
			msg := &(*msgs)[i]

			// todo: handle err
			if ok, _ := s.filterOutStunMessages(msg.Buffers, msg.N, msg.Addr); ok {
				continue
			}
			sizes[i] = msg.N
			if sizes[i] == 0 {
				continue
			}
			addrPort := msg.Addr.(*net.UDPAddr).AddrPort()

			if isTransportPkg(msg.Buffers, msg.N) {
				s.activityRecorder.record(addrPort)
			}

			ep := &wgConn.StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
			wgConn.GetSrcFromControl(msg.OOB[:msg.NN], ep)
			eps[i] = ep
		}
		return numMsgs, nil
	}
}

// createOrUpdateMux creates or updates the UDP mux with the available connections.
// Must be called with muUDPMux held.
func (s *ICEBind) createOrUpdateMux() {
	var muxConn net.PacketConn

	switch {
	case s.ipv4Conn != nil && s.ipv6Conn != nil:
		muxConn = NewDualStackPacketConn(
			nbnet.WrapPacketConn(s.ipv4Conn),
			nbnet.WrapPacketConn(s.ipv6Conn),
		)
	case s.ipv4Conn != nil:
		muxConn = nbnet.WrapPacketConn(s.ipv4Conn)
	case s.ipv6Conn != nil:
		muxConn = nbnet.WrapPacketConn(s.ipv6Conn)
	default:
		return
	}

	// Don't close the old mux - it doesn't own the underlying connections.
	// The sockets are managed by WireGuard's StdNetBind, not by us.
	s.udpMux = udpmux.NewUniversalUDPMuxDefault(
		udpmux.UniversalUDPMuxParams{
			UDPConn:   muxConn,
			Net:       s.transportNet,
			FilterFn:  s.filterFn,
			WGAddress: s.address,
			MTU:       s.mtu,
		},
	)
}

func (s *ICEBind) filterOutStunMessages(buffers [][]byte, n int, addr net.Addr) (bool, error) {
	for i := range buffers {
		if !stun.IsMessage(buffers[i]) {
			continue
		}

		msg, err := s.parseSTUNMessage(buffers[i][:n])
		if err != nil {
			buffers[i] = []byte{}
			return true, err
		}

		s.muUDPMux.Lock()
		mux := s.udpMux
		s.muUDPMux.Unlock()

		if mux != nil {
			if muxErr := mux.HandleSTUNMessage(msg, addr); muxErr != nil {
				log.Warnf("failed to handle STUN packet: %v", muxErr)
			}
		}

		buffers[i] = []byte{}
		return true, nil
	}
	return false, nil
}

func (s *ICEBind) parseSTUNMessage(raw []byte) (*stun.Message, error) {
	msg := &stun.Message{
		Raw: raw,
	}
	if err := msg.Decode(); err != nil {
		return nil, err
	}

	return msg, nil
}

// receiveRelayed is a receive function that is used to receive packets from the relayed connection and forward to the
// WireGuard. Critical part is do not block if the Closed() has been called.
func (c *ICEBind) receiveRelayed(buffs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
	c.closedChanMu.RLock()
	defer c.closedChanMu.RUnlock()

	select {
	case <-c.closedChan:
		return 0, net.ErrClosed
	case msg, ok := <-c.recvChan:
		if !ok {
			return 0, net.ErrClosed
		}
		copy(buffs[0], msg.Buffer)
		sizes[0] = len(msg.Buffer)
		eps[0] = wgConn.Endpoint(msg.Endpoint)

		if isTransportPkg(buffs, sizes[0]) {
			if ep, ok := eps[0].(*Endpoint); ok {
				c.activityRecorder.record(ep.AddrPort)
			}
		}

		return 1, nil
	}
}

func getMessages(msgsPool *sync.Pool) *[]ipv6.Message {
	return msgsPool.Get().(*[]ipv6.Message)
}

func putMessages(msgs *[]ipv6.Message, msgsPool *sync.Pool) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	msgsPool.Put(msgs)
}

func isTransportPkg(buffers [][]byte, n int) bool {
	// The first buffer should contain at least 4 bytes for type
	if len(buffers[0]) < 4 {
		return true
	}

	// WireGuard packet type is a little-endian uint32 at start
	packetType := binary.LittleEndian.Uint32(buffers[0][:4])

	// Check if packetType matches known WireGuard message types
	if packetType == 4 && n > 32 {
		return true
	}
	return false
}
