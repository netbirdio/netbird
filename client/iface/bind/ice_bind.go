package bind

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"github.com/pion/stun/v2"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wgConn "golang.zx2c4.com/wireguard/conn"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type RecvMessage struct {
	Endpoint *Endpoint
	Buffer   []byte
}

type receiverCreator struct {
	iceBind *ICEBind
}

func (rc receiverCreator) CreateIPv4ReceiverFn(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool, msgPool *sync.Pool) wgConn.ReceiveFunc {
	return rc.iceBind.createIPv4ReceiverFn(pc, conn, rxOffload, msgPool)
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
	RecvChan chan RecvMessage

	transportNet transport.Net
	filterFn     FilterFn
	endpoints    map[netip.Addr]net.Conn
	endpointsMu  sync.Mutex
	// every time when Close() is called (i.e. BindUpdate()) we need to close exit from the receiveRelayed and create a
	// new closed channel. With the closedChanMu we can safely close the channel and create a new one
	closedChan   chan struct{}
	closedChanMu sync.RWMutex // protect the closeChan recreation from reading from it.
	closed       bool

	muUDPMux sync.Mutex
	udpMux   *UniversalUDPMuxDefault
	address  wgaddr.Address
}

func NewICEBind(transportNet transport.Net, filterFn FilterFn, address wgaddr.Address) *ICEBind {
	b, _ := wgConn.NewStdNetBind().(*wgConn.StdNetBind)
	ib := &ICEBind{
		StdNetBind:   b,
		RecvChan:     make(chan RecvMessage, 1),
		transportNet: transportNet,
		filterFn:     filterFn,
		endpoints:    make(map[netip.Addr]net.Conn),
		closedChan:   make(chan struct{}),
		closed:       true,
		address:      address,
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

	return s.StdNetBind.Close()
}

// GetICEMux returns the ICE UDPMux that was created and used by ICEBind
func (s *ICEBind) GetICEMux() (*UniversalUDPMuxDefault, error) {
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

func (s *ICEBind) createIPv4ReceiverFn(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool, msgsPool *sync.Pool) wgConn.ReceiveFunc {
	s.muUDPMux.Lock()
	defer s.muUDPMux.Unlock()

	s.udpMux = NewUniversalUDPMuxDefault(
		UniversalUDPMuxParams{
			UDPConn:   conn,
			Net:       s.transportNet,
			FilterFn:  s.filterFn,
			WGAddress: s.address,
		},
	)
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
				//nolint
				numMsgs, err = pc.ReadBatch((*msgs)[readAt:], 0)
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
			ok, _ := s.filterOutStunMessages(msg.Buffers, msg.N, msg.Addr)
			if ok {
				continue
			}
			sizes[i] = msg.N
			if sizes[i] == 0 {
				continue
			}
			addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
			ep := &wgConn.StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
			wgConn.GetSrcFromControl(msg.OOB[:msg.NN], ep)
			eps[i] = ep
		}
		return numMsgs, nil
	}
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

		muxErr := s.udpMux.HandleSTUNMessage(msg, addr)
		if muxErr != nil {
			log.Warnf("failed to handle STUN packet")
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
	case msg, ok := <-c.RecvChan:
		if !ok {
			return 0, net.ErrClosed
		}
		copy(buffs[0], msg.Buffer)
		sizes[0] = len(msg.Buffer)
		eps[0] = wgConn.Endpoint(msg.Endpoint)
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
