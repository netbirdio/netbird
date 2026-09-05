//go:build !android && !ios && !freebsd && !js

package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/desktop"
)

// Conn is the lazy, lock-protected gRPC connection shared by all services so they reuse one channel.
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

	// Lazy on purpose: grpc.NewClient does not connect here, so a daemon that
	// is down surfaces as a per-RPC Unavailable instead of blocking the UI.
	target, opts := daemonaddr.DialTarget(daemonaddr.ResolveDaemonAddr(c.addr))
	opts = append(opts,
		grpc.WithUserAgent(desktop.GetUIUserAgent()),
		// Cap reconnect backoff at 5s; gRPC's default 120s MaxDelay would
		// leave the UI waiting 30-60s to notice a freshly-started daemon.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   5 * time.Second,
			},
		}),
	)

	cc, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial daemon: %w", err)
	}
	c.client = proto.NewDaemonServiceClient(cc)
	return c.client, nil
}

// DaemonAddr returns the default daemon gRPC address: a Unix socket on
// Linux/macOS, a named pipe on Windows. The pipe carries the caller's token,
// which loopback TCP does not, so the daemon can tell who is calling.
func DaemonAddr() string {
	if runtime.GOOS == "windows" {
		return daemonaddr.WindowsPipeAddr
	}
	return "unix:///var/run/netbird.sock"
}
