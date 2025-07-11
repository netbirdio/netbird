package bind

import (
	"errors"
	"net"
	"time"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

var (
	errNoIPv4Conn  = errors.New("no IPv4 connection available")
	errNoIPv6Conn  = errors.New("no IPv6 connection available")
	errInvalidAddr = errors.New("invalid address type")
)

// DualStackPacketConn is a composite PacketConn that can handle both IPv4 and IPv6
type DualStackPacketConn struct {
	ipv4Conn net.PacketConn
	ipv6Conn net.PacketConn
}

// NewDualStackPacketConn creates a new dual-stack packet connection
func NewDualStackPacketConn(ipv4Conn, ipv6Conn net.PacketConn) *DualStackPacketConn {
	return &DualStackPacketConn{
		ipv4Conn: ipv4Conn,
		ipv6Conn: ipv6Conn,
	}
}

// ReadFrom reads from both IPv4 and IPv6 connections
func (d *DualStackPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Prefer IPv4 if available
	if d.ipv4Conn != nil {
		return d.ipv4Conn.ReadFrom(b)
	}
	if d.ipv6Conn != nil {
		return d.ipv6Conn.ReadFrom(b)
	}
	return 0, nil, net.ErrClosed
}

// WriteTo writes to the appropriate connection based on the address type
func (d *DualStackPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.OpError{
			Op:   "write",
			Net:  "udp",
			Addr: addr,
			Err:  errInvalidAddr,
		}
	}

	if udpAddr.IP.To4() == nil {
		if d.ipv6Conn != nil {
			return d.ipv6Conn.WriteTo(b, addr)
		}
		return 0, &net.OpError{
			Op:   "write",
			Net:  "udp6",
			Addr: addr,
			Err:  errNoIPv6Conn,
		}
	}

	if d.ipv4Conn != nil {
		return d.ipv4Conn.WriteTo(b, addr)
	}
	return 0, &net.OpError{
		Op:   "write",
		Net:  "udp4",
		Addr: addr,
		Err:  errNoIPv4Conn,
	}
}

// Close closes both connections
func (d *DualStackPacketConn) Close() error {
	var result *multierror.Error
	if d.ipv4Conn != nil {
		if err := d.ipv4Conn.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	if d.ipv6Conn != nil {
		if err := d.ipv6Conn.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

// LocalAddr returns the local address of the IPv4 connection (for compatibility)
func (d *DualStackPacketConn) LocalAddr() net.Addr {
	if d.ipv4Conn != nil {
		return d.ipv4Conn.LocalAddr()
	}
	if d.ipv6Conn != nil {
		return d.ipv6Conn.LocalAddr()
	}
	return nil
}

// SetDeadline sets the deadline for both connections
func (d *DualStackPacketConn) SetDeadline(t time.Time) error {
	var result *multierror.Error
	if d.ipv4Conn != nil {
		if err := d.ipv4Conn.SetDeadline(t); err != nil {
			result = multierror.Append(result, err)
		}
	}
	if d.ipv6Conn != nil {
		if err := d.ipv6Conn.SetDeadline(t); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

// SetReadDeadline sets the read deadline for both connections
func (d *DualStackPacketConn) SetReadDeadline(t time.Time) error {
	var result *multierror.Error
	if d.ipv4Conn != nil {
		if err := d.ipv4Conn.SetReadDeadline(t); err != nil {
			result = multierror.Append(result, err)
		}
	}
	if d.ipv6Conn != nil {
		if err := d.ipv6Conn.SetReadDeadline(t); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

// SetWriteDeadline sets the write deadline for both connections
func (d *DualStackPacketConn) SetWriteDeadline(t time.Time) error {
	var result *multierror.Error
	if d.ipv4Conn != nil {
		if err := d.ipv4Conn.SetWriteDeadline(t); err != nil {
			result = multierror.Append(result, err)
		}
	}
	if d.ipv6Conn != nil {
		if err := d.ipv6Conn.SetWriteDeadline(t); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}
