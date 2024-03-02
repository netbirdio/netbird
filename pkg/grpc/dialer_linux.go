//go:build !android

package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc"

	netpkg "github.com/netbirdio/netbird/pkg/net"
)

func NewCustomDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return netpkg.NewDialer().DialContext(ctx, "tcp", addr)
	})
}
