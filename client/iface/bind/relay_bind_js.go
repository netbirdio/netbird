//go:build js

package bind

import (
	"context"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
)

type recvMessage struct {
	Endpoint *Endpoint
	Buffer   []byte
}

type RelayBindJS struct {
	*conn.StdNetBind

	recvChan         chan recvMessage
	endpoints        map[netip.Addr]net.Conn
	endpointsMu      sync.Mutex
	activityRecorder *ActivityRecorder
	ctx              context.Context
	cancel           context.CancelFunc
}

func NewRelayBindJS() *RelayBindJS {
	return &RelayBindJS{
		recvChan:         make(chan recvMessage, 100),
		endpoints:        make(map[netip.Addr]net.Conn),
		activityRecorder: NewActivityRecorder(),
	}
}

// Open creates a receive function for handling relay packets in WASM.
func (s *RelayBindJS) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	log.Debugf("Open: creating receive function for port %d", uport)

	s.ctx, s.cancel = context.WithCancel(context.Background())

	receiveFn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-s.ctx.Done():
			return 0, net.ErrClosed
		case msg, ok := <-s.recvChan:
			if !ok {
				return 0, net.ErrClosed
			}
			copy(bufs[0], msg.Buffer)
			sizes[0] = len(msg.Buffer)
			eps[0] = conn.Endpoint(msg.Endpoint)
			return 1, nil
		}
	}

	log.Debugf("Open: receive function created, returning port %d", uport)
	return []conn.ReceiveFunc{receiveFn}, uport, nil
}

func (s *RelayBindJS) Close() error {
	log.Debugf("Close: returning from Close")
	s.cancel()
	return nil
}

func (s *RelayBindJS) ReceiveFromEndpoint(ctx context.Context, ep *Endpoint, buf []byte) {
	select {
	case <-s.ctx.Done():
		return
	case <-ctx.Done():
		return
	case s.recvChan <- recvMessage{ep, buf}:
	}
}

// Send forwards packets through the relay connection for WASM.
func (s *RelayBindJS) Send(bufs [][]byte, ep conn.Endpoint) error {
	if ep == nil {
		return nil
	}

	fakeIP := ep.DstIP()

	s.endpointsMu.Lock()
	relayConn, ok := s.endpoints[fakeIP]
	s.endpointsMu.Unlock()

	if !ok {
		return nil
	}

	for _, buf := range bufs {
		if _, err := relayConn.Write(buf); err != nil {
			log.Errorf("Send: failed to write to relay: %v", err)
			return err
		}
	}

	return nil
}

func (b *RelayBindJS) SetEndpoint(fakeIP netip.Addr, conn net.Conn) {
	b.endpointsMu.Lock()
	b.endpoints[fakeIP] = conn
	b.endpointsMu.Unlock()
}

func (s *RelayBindJS) RemoveEndpoint(fakeIP netip.Addr) {
	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	delete(s.endpoints, fakeIP)
}

// GetICEMux returns the ICE UDPMux that was created and used by ICEBind
func (s *RelayBindJS) GetICEMux() (*UniversalUDPMuxDefault, error) {
	return nil, ErrUDPMUXNotSupported
}

func (s *RelayBindJS) ActivityRecorder() *ActivityRecorder {
	return s.activityRecorder
}
