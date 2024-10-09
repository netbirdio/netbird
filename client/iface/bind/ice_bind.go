package bind

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"

	"github.com/pion/stun/v2"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

type RecvMessage struct {
	Endpoint *Endpoint
	Buffer   []byte
	Len      int
}

type receiverCreator struct {
	iceBind *ICEBind
}

func (rc receiverCreator) CreateIPv4ReceiverFn(msgPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn) wgConn.ReceiveFunc {
	return rc.iceBind.createIPv4ReceiverFn(msgPool, pc, conn)
}

type ICEBind struct {
	*wgConn.StdNetBind
	RecvChan chan RecvMessage

	transportNet transport.Net
	filterFn     FilterFn
	endpoints    map[string]net.Conn
	endpointsMu  sync.Mutex
	closedChan   chan struct{}

	muUDPMux sync.Mutex
	udpMux   *UniversalUDPMuxDefault
	closed   bool
}

func NewICEBind(transportNet transport.Net, filterFn FilterFn) *ICEBind {
	b, _ := wgConn.NewStdNetBind().(*wgConn.StdNetBind)
	ib := &ICEBind{
		StdNetBind:   b,
		RecvChan:     make(chan RecvMessage, 1),
		transportNet: transportNet,
		filterFn:     filterFn,
		endpoints:    make(map[string]net.Conn),
		closedChan:   make(chan struct{}),
		closed:       true,
	}

	rc := receiverCreator{
		ib,
	}
	ib.StdNetBind = wgConn.NewStdNetBindWithReceiverCreator(rc)
	return ib
}

func (s *ICEBind) Open(uport uint16) ([]wgConn.ReceiveFunc, uint16, error) {
	s.closed = false
	log.Infof("------ ICEBind: Open")
	fns, port, err := s.StdNetBind.Open(uport)
	if err != nil {
		return nil, 0, err
	}

	fns = append(fns, s.receiveRelayed)
	return fns, port, nil
}

func (s *ICEBind) Close() error {
	// just a quick implementation to make the tests pass
	if s.closed {
		return nil
	}
	log.Infof("------ ICEBind: Close")
	s.closed = true
	select {
	case s.closedChan <- struct{}{}:
	default:
	}
	err := s.StdNetBind.Close()
	return err

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

func (b *ICEBind) SetEndpoint(peerAddress *net.UDPAddr, conn net.Conn) (*net.UDPAddr, error) {
	fakeAddr, err := fakeAddress(peerAddress)
	if err != nil {
		return nil, err
	}
	b.endpointsMu.Lock()
	b.endpoints[fakeAddr.String()] = conn
	b.endpointsMu.Unlock()
	return fakeAddr, nil
}

func (b *ICEBind) RemoveEndpoint(fakeAddr *net.UDPAddr) {
	b.endpointsMu.Lock()
	defer b.endpointsMu.Unlock()
	delete(b.endpoints, fakeAddr.String())
}

func (b *ICEBind) Send(bufs [][]byte, ep wgConn.Endpoint) error {
	b.endpointsMu.Lock()
	conn, ok := b.endpoints[ep.DstToString()]
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

func (s *ICEBind) createIPv4ReceiverFn(ipv4MsgsPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn) wgConn.ReceiveFunc {
	s.muUDPMux.Lock()
	defer s.muUDPMux.Unlock()

	s.udpMux = NewUniversalUDPMuxDefault(
		UniversalUDPMuxParams{
			UDPConn:  conn,
			Net:      s.transportNet,
			FilterFn: s.filterFn,
		},
	)
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (n int, err error) {
		msgs := ipv4MsgsPool.Get().(*[]ipv4.Message)
		defer ipv4MsgsPool.Put(msgs)
		for i := range bufs {
			(*msgs)[i].Buffers[0] = bufs[i]
		}
		var numMsgs int
		if runtime.GOOS == "linux" {
			numMsgs, err = pc.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, err
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
				sizes[i] = 0
			} else {
				sizes[i] = msg.N
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

func (c *ICEBind) receiveRelayed(buffs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
	if c.closed {
		log.Infof("receiver is closed, return with closed error")
		return 0, net.ErrClosed
	}

	select {
	case <-c.closedChan:
		return 0, net.ErrClosed
	case msg, ok := <-c.RecvChan:
		if !ok {
			return 0, net.ErrClosed
		}
		// todo: do not copy the full buffer
		copy(buffs[0], msg.Buffer)
		sizes[0] = msg.Len
		eps[0] = wgConn.Endpoint(msg.Endpoint)
		return 1, nil
	}
}

func fakeAddress(peerAddress *net.UDPAddr) (*net.UDPAddr, error) {
	octets := strings.Split(peerAddress.IP.String(), ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("invalid IP format")
	}

	newAddr := &net.UDPAddr{
		IP:   net.ParseIP(fmt.Sprintf("127.1.%s.%s", octets[2], octets[3])),
		Port: peerAddress.Port,
	}
	return newAddr, nil
}
