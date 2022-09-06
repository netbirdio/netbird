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

type ICEBind struct {
	sharedConn net.PacketConn
	iceMux     *UniversalUDPMuxDefault

	mu sync.Mutex // protects following fields
}

func (b *ICEBind) GetSharedConn() (net.PacketConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sharedConn == nil {
		return nil, fmt.Errorf("ICEBind has not been initialized yet")
	}

	return b.sharedConn, nil
}

func (b *ICEBind) GetICEMux() (UniversalUDPMux, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.iceMux == nil {
		return nil, fmt.Errorf("ICEBind has not been initialized yet")
	}

	return b.iceMux, nil
}

func (b *ICEBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sharedConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	port := int(uport)
	ipv4Conn, port, err := listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	b.sharedConn = ipv4Conn
	b.iceMux = NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: b.sharedConn})

	portAddr, err := netip.ParseAddrPort(ipv4Conn.LocalAddr().String())
	if err != nil {
		return nil, 0, err
	}
	return []conn.ReceiveFunc{b.makeReceiveIPv4(b.sharedConn)}, portAddr.Port(), nil
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

func (b *ICEBind) makeReceiveIPv4(c net.PacketConn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, endpoint, err := c.ReadFrom(buff)
		if err != nil {
			return 0, nil, err
		}
		e, err := netip.ParseAddrPort(endpoint.String())
		if err != nil {
			return 0, nil, err
		}
		if !stun.IsMessage(buff[:n]) {
			// WireGuard traffic
			return n, (*conn.StdNetEndpoint)(&net.UDPAddr{
				IP:   e.Addr().AsSlice(),
				Port: int(e.Port()),
				Zone: e.Addr().Zone(),
			}), nil
		}

		err = b.iceMux.HandlePacket(buff, n, endpoint)
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

	var err1, err2 error
	if b.sharedConn != nil {
		c := b.sharedConn
		b.sharedConn = nil
		err1 = c.Close()
	}

	if b.iceMux != nil {
		m := b.iceMux
		b.iceMux = nil
		err2 = m.Close()
	}

	if err1 != nil {
		return err1
	}
	return err2
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
	_, err := b.sharedConn.WriteTo(buff, (*net.UDPAddr)(nend))
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
