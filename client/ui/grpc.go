//go:build !android && !ios && !freebsd && !js

package main

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/desktop"
)

// Conn is a lazy, lock-protected gRPC connection to the NetBird daemon.
// One Conn instance is shared by all services so they reuse the same channel.
type Conn struct {
	addr string

	mu     sync.Mutex
	client proto.DaemonServiceClient
}

func NewConn(addr string) *Conn {
	return &Conn{addr: addr}
}

func (c *Conn) Client() (proto.DaemonServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}

	cc, err := grpc.NewClient(
		strings.TrimPrefix(c.addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUserAgent(desktop.GetUIUserAgent()),
		// Without ConnectParams the SubChannel uses gRPC's default 120s
		// MaxDelay, so after a couple of failed dials the UI waits 30-60s
		// before noticing a freshly-started daemon. The Wails UI is a
		// desktop client expecting prompt reconnects, not a high-fanout
		// backend, so a 5s cap is a better trade-off than the default.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   5 * time.Second,
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial daemon: %w", err)
	}
	c.client = proto.NewDaemonServiceClient(cc)
	return c.client, nil
}

// DaemonAddr returns the default daemon gRPC address for the current OS.
// Linux/macOS use a Unix socket; Windows uses TCP loopback.
func DaemonAddr() string {
	if runtime.GOOS == "windows" {
		return "tcp://127.0.0.1:41731"
	}
	return "unix:///var/run/netbird.sock"
}
