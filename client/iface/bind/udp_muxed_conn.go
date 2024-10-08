package bind

/*
 Most of this code was copied from https://github.com/pion/ice and modified to fulfill NetBird's requirements
*/

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v3/packetio"
)

type udpMuxedConnParams struct {
	Mux       *UDPMuxDefault
	AddrPool  *sync.Pool
	Key       string
	LocalAddr net.Addr
	Logger    logging.LeveledLogger
}

// udpMuxedConn represents a logical packet conn for a single remote as identified by ufrag
type udpMuxedConn struct {
	params *udpMuxedConnParams
	// remote addresses that we have sent to on this conn
	addresses []string

	// channel holding incoming packets
	buf        *packetio.Buffer
	closedChan chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex
}

func newUDPMuxedConn(params *udpMuxedConnParams) *udpMuxedConn {
	p := &udpMuxedConn{
		params:     params,
		buf:        packetio.NewBuffer(),
		closedChan: make(chan struct{}),
	}

	return p
}

func (c *udpMuxedConn) ReadFrom(b []byte) (n int, rAddr net.Addr, err error) {
	buf := c.params.AddrPool.Get().(*bufferHolder) //nolint:forcetypeassert
	defer c.params.AddrPool.Put(buf)

	// read address
	total, err := c.buf.Read(buf.buf)
	if err != nil {
		return 0, nil, err
	}

	dataLen := int(binary.LittleEndian.Uint16(buf.buf[:2]))
	if dataLen > total || dataLen > len(b) {
		return 0, nil, io.ErrShortBuffer
	}

	// read data and then address
	offset := 2
	copy(b, buf.buf[offset:offset+dataLen])
	offset += dataLen

	// read address len & decode address
	addrLen := int(binary.LittleEndian.Uint16(buf.buf[offset : offset+2]))
	offset += 2

	if rAddr, err = decodeUDPAddr(buf.buf[offset : offset+addrLen]); err != nil {
		return 0, nil, err
	}

	return dataLen, rAddr, nil
}

func (c *udpMuxedConn) WriteTo(buf []byte, rAddr net.Addr) (n int, err error) {
	if c.isClosed() {
		return 0, io.ErrClosedPipe
	}
	// each time we write to a new address, we'll register it with the mux
	addr := rAddr.String()
	if !c.containsAddress(addr) {
		c.addAddress(addr)
	}

	return c.params.Mux.writeTo(buf, rAddr)
}

func (c *udpMuxedConn) LocalAddr() net.Addr {
	return c.params.LocalAddr
}

func (c *udpMuxedConn) SetDeadline(tm time.Time) error {
	return nil
}

func (c *udpMuxedConn) SetReadDeadline(tm time.Time) error {
	return nil
}

func (c *udpMuxedConn) SetWriteDeadline(tm time.Time) error {
	return nil
}

func (c *udpMuxedConn) CloseChannel() <-chan struct{} {
	return c.closedChan
}

func (c *udpMuxedConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.buf.Close()
		close(c.closedChan)
	})
	return err
}

func (c *udpMuxedConn) isClosed() bool {
	select {
	case <-c.closedChan:
		return true
	default:
		return false
	}
}

func (c *udpMuxedConn) getAddresses() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	addresses := make([]string, len(c.addresses))
	copy(addresses, c.addresses)
	return addresses
}

func (c *udpMuxedConn) addAddress(addr string) {
	c.mu.Lock()
	c.addresses = append(c.addresses, addr)
	c.mu.Unlock()

	// map it on mux
	c.params.Mux.registerConnForAddress(c, addr)
}

func (c *udpMuxedConn) containsAddress(addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.addresses {
		if addr == a {
			return true
		}
	}
	return false
}

func (c *udpMuxedConn) writePacket(data []byte, addr *net.UDPAddr) error {
	// write two packets, address and data
	buf := c.params.AddrPool.Get().(*bufferHolder) //nolint:forcetypeassert
	defer c.params.AddrPool.Put(buf)

	// format of buffer | data len | data bytes | addr len | addr bytes |
	if len(buf.buf) < len(data)+maxAddrSize {
		return io.ErrShortBuffer
	}
	// data len
	binary.LittleEndian.PutUint16(buf.buf, uint16(len(data)))
	offset := 2

	// data
	copy(buf.buf[offset:], data)
	offset += len(data)

	// write address first, leaving room for its length
	n, err := encodeUDPAddr(addr, buf.buf[offset+2:])
	if err != nil {
		return err
	}
	total := offset + n + 2

	// address len
	binary.LittleEndian.PutUint16(buf.buf[offset:], uint16(n))

	if _, err := c.buf.Write(buf.buf[:total]); err != nil {
		return err
	}
	return nil
}

func encodeUDPAddr(addr *net.UDPAddr, buf []byte) (int, error) {
	ipData, err := addr.IP.MarshalText()
	if err != nil {
		return 0, err
	}
	total := 2 + len(ipData) + 2 + len(addr.Zone)
	if total > len(buf) {
		return 0, io.ErrShortBuffer
	}

	binary.LittleEndian.PutUint16(buf, uint16(len(ipData)))
	offset := 2
	n := copy(buf[offset:], ipData)
	offset += n
	binary.LittleEndian.PutUint16(buf[offset:], uint16(addr.Port))
	offset += 2
	copy(buf[offset:], addr.Zone)
	return total, nil
}

func decodeUDPAddr(buf []byte) (*net.UDPAddr, error) {
	addr := net.UDPAddr{}

	offset := 0
	ipLen := int(binary.LittleEndian.Uint16(buf[:2]))
	offset += 2
	// basic bounds checking
	if ipLen+offset > len(buf) {
		return nil, io.ErrShortBuffer
	}
	if err := addr.IP.UnmarshalText(buf[offset : offset+ipLen]); err != nil {
		return nil, err
	}
	offset += ipLen
	addr.Port = int(binary.LittleEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	zone := make([]byte, len(buf[offset:]))
	copy(zone, buf[offset:])
	addr.Zone = string(zone)

	return &addr, nil
}
