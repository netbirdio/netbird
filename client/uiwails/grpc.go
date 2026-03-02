//go:build !(linux && 386)

package main

import (
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

const (
	defaultFailTimeout = 3 * time.Second
	failFastTimeout    = time.Second
)

// GRPCClient manages a single persistent gRPC connection to the NetBird daemon.
type GRPCClient struct {
	addr   string
	mu     sync.Mutex
	conn   *grpc.ClientConn
	client proto.DaemonServiceClient
}

// NewGRPCClient creates a new GRPCClient for the given daemon address.
func NewGRPCClient(addr string) *GRPCClient {
	return &GRPCClient{addr: addr}
}

// GetClient returns a cached DaemonServiceClient, creating the connection on first use.
func (g *GRPCClient) GetClient(timeout time.Duration) (proto.DaemonServiceClient, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.client != nil {
		return g.client, nil
	}

	target := g.addr
	if strings.HasPrefix(target, "tcp://") {
		target = strings.TrimPrefix(target, "tcp://")
	} else if strings.HasPrefix(target, "unix://") {
		target = "unix:" + strings.TrimPrefix(target, "unix://")
	}

	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUserAgent(getUIUserAgent()),
	)
	if err != nil {
		return nil, err
	}

	g.conn = conn
	g.client = proto.NewDaemonServiceClient(conn)
	log.Debugf("gRPC connection established to %s", g.addr)

	return g.client, nil
}

// Close closes the underlying gRPC connection.
func (g *GRPCClient) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.conn != nil {
		err := g.conn.Close()
		g.conn = nil
		g.client = nil
		return err
	}
	return nil
}

func getUIUserAgent() string {
	return "netbird-fancyui/" + version.NetbirdVersion()
}
