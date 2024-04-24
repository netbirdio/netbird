package bind

import (
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/pion/stun/v2"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

type ICEBind struct {
	*wgConn.StdNetBind

	muUDPMux sync.Mutex

	transportNet transport.Net
	udpMux       *UniversalUDPMuxDefault

	receiverCreator *receiverCreator
}

func NewICEBind(transportNet transport.Net) *ICEBind {
	ib := &ICEBind{
		transportNet: transportNet,
	}

	rc := newReceiverCreator(ib)
	ib.receiverCreator = rc

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

func (s *ICEBind) SetTurnConn(conn interface{}) {
	s.receiverCreator.setTurnConn(conn)
}

func (s *ICEBind) createIPv4ReceiverFn(ipv4MsgsPool *sync.Pool, pc *ipv4.PacketConn, conn *net.UDPConn, netConn net.PacketConn) wgConn.ReceiveFunc {
	s.muUDPMux.Lock()
	defer s.muUDPMux.Unlock()

	if conn != nil {
		s.udpMux = NewUniversalUDPMuxDefault(
			UniversalUDPMuxParams{
				UDPConn: conn,
				Net:     s.transportNet,
			},
		)
	}
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (n int, err error) {
		msgs := ipv4MsgsPool.Get().(*[]ipv4.Message)
		defer ipv4MsgsPool.Put(msgs)
		for i := range bufs {
			(*msgs)[i].Buffers[0] = bufs[i]
		}
		var numMsgs int
		if runtime.GOOS == "linux" {
			if netConn != nil {
				log.Debugf("----read from turn conn...")
				msg := &(*msgs)[0]
				msg.N, msg.Addr, err = netConn.ReadFrom(msg.Buffers[0])
				if err != nil {
					return 0, err
				}
				log.Debugf("----msg address is: %s, size: %d", msg.Addr.String(), msg.N)
				numMsgs = 1
			} else {
				log.Debugf("----read from pc...")
				numMsgs, err = pc.ReadBatch(*msgs, 0)
				if err != nil {
					return 0, err
				}
			}
		} else {
			if netConn != nil {
				log.Debugf("----read from turn conn...")
				msg := &(*msgs)[0]
				msg.N, msg.Addr, err = netConn.ReadFrom(msg.Buffers[0])
				if err != nil {
					return 0, err
				}
				log.Debugf("----msg address is: %s, size: %d", msg.Addr.String(), msg.N)
				numMsgs = 1
			} else {
				msg := &(*msgs)[0]
				msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
				if err != nil {
					return 0, err
				}
				numMsgs = 1
			}
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
			ep := &wgConn.StdNetEndpoint{
				AddrPort: addrPort,
				Conn:     netConn,
			}
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
