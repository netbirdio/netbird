package iface

import (
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"net/netip"
	"sync"
)

type UserEndpoint struct {
	conn.StdNetEndpoint
}

type packet struct {
	buff []byte
	addr *net.UDPAddr
}

type UserBind struct {
	endpointsLock sync.RWMutex
	endpoints     map[netip.AddrPort]*UserEndpoint
	sharedConn    net.PacketConn

	Packets     chan packet
	closeSignal chan struct{}
}

func NewUserBind(sharedConn net.PacketConn) *UserBind {
	return &UserBind{sharedConn: sharedConn}
}

func (b *UserBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {

	b.Packets = make(chan packet, 1000)
	b.closeSignal = make(chan struct{})

	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *UserBind) receive(buff []byte) (int, conn.Endpoint, error) {

	/*n, endpoint, err := b.sharedConn.ReadFrom(buff)
	if err != nil {
		return 0, nil, err
	}
	e, err := netip.ParseAddrPort(endpoint.String())
	if err != nil {
		return 0, nil, err
	}
	return n, (*conn.StdNetEndpoint)(&net.UDPAddr{
		IP:   e.addr().AsSlice(),
		Port: int(e.Port()),
		Zone: e.addr().Zone(),
	}), err*/

	select {
	case <-b.closeSignal:
		return 0, nil, net.ErrClosed
	case pkt := <-b.Packets:
		/*log.Infof("received packet %d from %s to copy to buffer %d", binary.Size(pkt.buff), pkt.addr.String(),
		len(buff))*/
		return copy(buff, pkt.buff), (*conn.StdNetEndpoint)(pkt.addr), nil
	}
}

func (b *UserBind) Close() error {
	if b.closeSignal != nil {
		select {
		case <-b.closeSignal:
		default:
			close(b.closeSignal)
		}
	}
	return nil
}

// SetMark sets the mark for each packet sent through this Bind.
// This mark is passed to the kernel as the socket option SO_MARK.
func (b *UserBind) SetMark(mark uint32) error {
	return nil
}

func (b *UserBind) Send(buff []byte, endpoint conn.Endpoint) error {
	nend, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	//log.Infof("sending packet %d from %s to %s", binary.Size(buff), b.sharedConn.LocalAddr().String(), (*net.UDPAddr)(nend).String())

	_, err := b.sharedConn.WriteTo(buff, (*net.UDPAddr)(nend))
	return err
}

// ParseEndpoint creates a new endpoint from a string.
func (b *UserBind) ParseEndpoint(s string) (ep conn.Endpoint, err error) {
	e, err := netip.ParseAddrPort(s)
	return (*conn.StdNetEndpoint)(&net.UDPAddr{
		IP:   e.Addr().AsSlice(),
		Port: int(e.Port()),
		Zone: e.Addr().Zone(),
	}), err
}

func (b *UserBind) OnData(buff []byte, addr *net.UDPAddr) {
	b.Packets <- packet{
		buff: buff,
		addr: addr,
	}
}
