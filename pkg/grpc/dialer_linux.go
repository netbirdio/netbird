//go:build !android

package grpc

import (
	"context"
	"fmt"
	"net"
	"syscall"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func NewCustomDialer(fwmark int) grpc.DialOption {
	return NewDialerWithFwmark(fwmark)
}

// NewDialerWithFwmark returns a grpc.DialOption that sets the firewall mark for the connection.
func NewDialerWithFwmark(fwmark int) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("resolve TCP address failed: %w", err)
		}

		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("dial TCP failed: %w", err)
		}

		tcpConnFile, err := conn.File()
		if err != nil {
			return nil, fmt.Errorf("retrieve file descriptor failed: %w", err)
		}
		defer func() {
			if err := tcpConnFile.Close(); err != nil {
				log.Errorf("gPRC dialer: closing file descriptor failed: %v", err)
			}
		}()

		fd := int(tcpConnFile.Fd())
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, fwmark); err != nil {
			return nil, fmt.Errorf("set socket option failed: %w", err)
		}

		if err := syscall.SetNonblock(fd, true); err != nil {
			return nil, fmt.Errorf("set non-blocking failed: %w", err)
		}

		return conn, nil
	})
}
