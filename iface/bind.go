package iface

import (
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"net/netip"
	"sync"
)

type packets struct {
	buff []byte
	addr net.UDPAddr
}

type ICEBind struct {
	mu          sync.Mutex
	packets     chan packets
	closeSignal chan struct{}
	conn        *net.UDPConn
}

func NewICEBind(udpConn *net.UDPConn) *ICEBind {
	return &ICEBind{
		conn: udpConn,
		mu:   sync.Mutex{},
	}
}

func (bind *ICEBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {

	bind.mu.Lock()
	defer bind.mu.Unlock()
	log.Infof("opening Bind on port %d", port)

	udpConn, p, err := listenNet("udp4", int(port))
	if err != nil {
		return nil, 0, err
	}
	bind.conn = udpConn
	return []conn.ReceiveFunc{bind.makeReceiveIPv4(udpConn)}, uint16(p), nil

	/*bind.packets = make(chan packets)
	bind.closeSignal = make(chan struct{})

	addrPort, err := netip.ParseAddrPort(bind.conn.LocalAddr().String())
	if err != nil {
		return nil, 0, err
	}

	return []conn.ReceiveFunc{bind.makeReceiveIPv4(bind.conn)}, addrPort.Port(), nil*/
}

func (bind *ICEBind) fakeReceiveIPv4(c *net.UDPConn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		return 0, nil, nil
	}
}

func (bind *ICEBind) makeReceiveIPv4(c *net.UDPConn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, endpoint, err := c.ReadFromUDP(buff)
		if endpoint != nil {
			endpoint.IP = endpoint.IP.To4()
		}
		return n, (*conn.StdNetEndpoint)(endpoint), err
	}
}

/*func (bind *ICEBind) receive(buff []byte) (int, conn.Endpoint, error) {
	n, endpoint, err := bind.conn.ReadFromUDP(buff)
	if endpoint != nil {
		endpoint.IP = endpoint.IP.To4()
	}
	return n, (*conn.StdNetEndpoint)(endpoint), err

	select {
	case <-bind.closeSignal:
		return 0, nil, net.ErrClosed
	case pkt := <-bind.packets:
		return copy(buf, pkt.buff), (*conn.StdNetEndpoint)(&pkt.addr), nil
	}
}*/

func (bind *ICEBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	err := bind.conn.Close()
	if err != nil {
		return err
	}

	if bind.closeSignal != nil {
		select {
		case <-bind.closeSignal:
		default:
			close(bind.closeSignal)
		}
		bind.packets = nil
	}
	return nil
}

// SetMark sets the mark for each packet sent through this Bind.
// This mark is passed to the kernel as the socket option SO_MARK.
func (bind *ICEBind) SetMark(mark uint32) error {
	return nil
}

func (bind *ICEBind) Send(buf []byte, endpoint conn.Endpoint) error {

	nend, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	_, err := bind.conn.WriteToUDP(buf, (*net.UDPAddr)(nend))
	return err
}

// ParseEndpoint creates a new endpoint from a string.
func (bind *ICEBind) ParseEndpoint(s string) (ep conn.Endpoint, err error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}

	return (*conn.StdNetEndpoint)(&net.UDPAddr{
		IP:   ap.Addr().AsSlice(),
		Port: int(ap.Port()),
		Zone: ap.Addr().Zone(),
	}), err
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
