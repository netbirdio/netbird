package iface

import (
	"errors"
	"fmt"
	"github.com/pion/stun"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"net/netip"
	"sync"
	"syscall"
)

type BindMux interface {
	HandlePacket(p []byte, n int, addr net.Addr) error
	Type() string
}

type ICEBind struct {
	sharedConn     net.PacketConn
	sharedConnHost net.PacketConn
	iceSrflxMux    *UniversalUDPMuxDefault
	iceHostMux     *UDPMuxDefault

	endpointMap map[string]net.PacketConn

	mu sync.Mutex // protects following fields
}

func (b *ICEBind) GetICEMux() (UniversalUDPMux, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.iceSrflxMux == nil {
		return nil, fmt.Errorf("ICEBind has not been initialized yet")
	}

	return b.iceSrflxMux, nil
}

func (b *ICEBind) GetICEHostMux() (UDPMux, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.iceHostMux == nil {
		return nil, fmt.Errorf("ICEBind has not been initialized yet")
	}

	return b.iceHostMux, nil
}

func (b *ICEBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sharedConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.sharedConnHost != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	b.endpointMap = make(map[string]net.PacketConn)

	port := int(uport)
	ipv4Conn, port, err := listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	ipv4ConnHost, port, err := listenNet("udp4", 0)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	b.sharedConn = ipv4Conn
	b.sharedConnHost = ipv4ConnHost
	b.iceSrflxMux = NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: b.sharedConn})
	b.iceHostMux = NewUDPMuxDefault(UDPMuxParams{UDPConn: b.sharedConnHost})

	portAddr, err := netip.ParseAddrPort(ipv4Conn.LocalAddr().String())
	if err != nil {
		return nil, 0, err
	}
	return []conn.ReceiveFunc{
			b.makeReceiveIPv4(b.sharedConn, b.iceSrflxMux),
			b.makeReceiveIPv4(b.sharedConnHost, b.iceHostMux),
		},
		portAddr.Port(), nil
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn, uaddr.Port, nil
}

func (b *ICEBind) makeReceiveIPv4(c net.PacketConn, bindMux BindMux) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, endpoint, err := c.ReadFrom(buff)
		if err != nil {
			return 0, nil, err
		}
		e, err := netip.ParseAddrPort(endpoint.String())
		if err != nil {
			return 0, nil, err
		}
		if !stun.IsMessage(buff[:20]) {
			// WireGuard traffic
			return n, (*conn.StdNetEndpoint)(&net.UDPAddr{
				IP:   e.Addr().AsSlice(),
				Port: int(e.Port()),
				Zone: e.Addr().Zone(),
			}), nil
		}

		b.mu.Lock()
		if _, ok := b.endpointMap[e.String()]; !ok {
			b.endpointMap[e.String()] = c
			log.Infof("added %s endpoint %s", bindMux.Type(), e.String())
		}
		b.mu.Unlock()

		err = bindMux.HandlePacket(buff, n, endpoint)
		if err != nil {
			return 0, nil, err
		}
		if err != nil {
			log.Warnf("failed to handle packet")
		}

		// discard packets because they are STUN related
		return 0, nil, nil //todo proper return
	}
}

func (b *ICEBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var err1, err2, err3, err4 error
	if b.sharedConn != nil {
		c := b.sharedConn
		b.sharedConn = nil
		err1 = c.Close()
	}
	if b.sharedConnHost != nil {
		c := b.sharedConnHost
		b.sharedConnHost = nil
		err2 = c.Close()
	}

	if b.iceSrflxMux != nil {
		m := b.iceSrflxMux
		b.iceSrflxMux = nil
		err3 = m.Close()
	}

	if b.iceHostMux != nil {
		m := b.iceHostMux
		b.iceHostMux = nil
		err4 = m.Close()
	}

	//todo close iceSrflxMux

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	if err3 != nil {
		return err3
	}

	return err4
}

// SetMark sets the mark for each packet sent through this Bind.
// This mark is passed to the kernel as the socket option SO_MARK.
func (b *ICEBind) SetMark(mark uint32) error {
	return nil
}

func (b *ICEBind) Send(buff []byte, endpoint conn.Endpoint) error {
	nend, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	b.mu.Lock()
	co := b.endpointMap[(*net.UDPAddr)(nend).String()]

	if co == nil {
		// todo proper handling
		// todo without it relayed connections didn't work. investigate
		log.Warnf("conn not found for endpoint %s", (*net.UDPAddr)(nend).String())
		co = b.sharedConn
		b.endpointMap[(*net.UDPAddr)(nend).String()] = b.sharedConn
		//return conn.ErrWrongEndpointType
	}
	b.mu.Unlock()

	_, err := co.WriteTo(buff, (*net.UDPAddr)(nend))
	return err
}

// ParseEndpoint creates a new endpoint from a string.
func (b *ICEBind) ParseEndpoint(s string) (ep conn.Endpoint, err error) {
	e, err := netip.ParseAddrPort(s)
	return (*conn.StdNetEndpoint)(&net.UDPAddr{
		IP:   e.Addr().AsSlice(),
		Port: int(e.Port()),
		Zone: e.Addr().Zone(),
	}), err
}
