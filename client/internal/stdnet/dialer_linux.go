//go:build !android

package stdnet

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/iface"
)

// dialFunc is a function type that abstracts different types of dial operations.
type dialFunc func(network, address string) (net.Conn, error)

// dialCommon handles the common dialing logic for any network type.
func (n *Net) dialCommon(dial dialFunc, network, address string) (net.Conn, error) {
	conn, err := dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", address, err)
	}

	if err := setFwmark(conn); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			log.Errorf("closing connection failed: %v", closeErr)
		}
		return nil, fmt.Errorf("setting fwmark on connection: %w", err)
	}

	return conn, nil
}

// Dial connects to the address on the named network.
func (n *Net) Dial(network, address string) (net.Conn, error) {
	return n.dialCommon(net.Dial, network, address)
}

// DialUDP connects to the address on the named UDP network.
func (n *Net) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.dialCommon(func(network, address string) (net.Conn, error) {
		return net.DialUDP(network, laddr, raddr)
	}, network, raddr.String())

	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

// DialTCP connects to the address on the named TCP network.
func (n *Net) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	conn, err := n.dialCommon(func(network, address string) (net.Conn, error) {
		return net.DialTCP(network, laddr, raddr)
	}, network, raddr.String())

	if err != nil {
		return nil, err
	}

	return conn.(*net.TCPConn), nil
}

// setFwmark sets the fwmark on the given connection.
func setFwmark(conn net.Conn) error {
	file, err := fileDescriptorFromConn(conn)
	if err != nil {
		return fmt.Errorf("get file descriptor: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("Closing file descriptor failed: %v", err)
		}
	}()

	fd := int(file.Fd())
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, iface.NetbirdFwmark); err != nil {
		return fmt.Errorf("setting SO_MARK: %w", err)
	}
	return nil
}

// fileDescriptorFromConn attempts to extract the file descriptor from a net.Conn.
// It supports *net.TCPConn and *net.UDPConn types.
func fileDescriptorFromConn(conn net.Conn) (file *os.File, err error) {
	switch c := conn.(type) {
	case *net.TCPConn:
		file, err = c.File()
	case *net.UDPConn:
		file, err = c.File()
	default:
		err = fmt.Errorf("connection type does not support fwmark setting")
	}
	if err != nil {
		return nil, fmt.Errorf("retrieving file descriptor: %w", err)
	}
	return file, nil
}
