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

type receiverCreator struct {
	iceBind *ICEBind
}

func (rc receiverCreator) CreateIPv4ReceiverFn(msgPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn) wgConn.ReceiveFunc {
	return rc.iceBind.createIPv4ReceiverFn(msgPool, pc, conn)
}

type ICEBind struct {
	*wgConn.StdNetBind

	muUDPMux sync.Mutex

	transportNet transport.Net
	filterFn     FilterFn
	endpoints    map[string]net.Conn

	udpMux *UniversalUDPMuxDefault
}

func NewICEBind(transportNet transport.Net, filterFn FilterFn) *ICEBind {
	ib := &ICEBind{
		transportNet: transportNet,
		filterFn:     filterFn,
		endpoints:    make(map[string]net.Conn),
	}

	rc := receiverCreator{
		ib,
	}
	ib.StdNetBind = wgConn.NewStdNetBindWithReceiverCreator(rc)
	return ib
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
	b.endpoints[fakeAddr.String()] = conn
	return fakeAddr, nil
}

func (b *ICEBind) RemoveEndpoint(fakeAddr *net.UDPAddr) {
	delete(b.endpoints, fakeAddr.String())
}

func (b *ICEBind) Send(bufs [][]byte, ep wgConn.Endpoint) error {
	conn, ok := b.endpoints[ep.DstToString()]
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

			log.Infof("---- read msg: %s", msg.Addr.String())
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
			log.Infof("---- ep msg: %v", ep)
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
