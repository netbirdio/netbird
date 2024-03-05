//go:build !android

package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func NewCustomDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return nbnet.NewDialer().DialContext(ctx, "tcp", addr)
	})
}
