package grpc

import (
	"context"
	"net"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func WithCustomDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := nbnet.NewDialer().DialContext(ctx, "tcp", addr)
		if err != nil {
			log.Errorf("Failed to dial: %s", err)
			return nil, err
		}
		return conn, nil
	})
}
