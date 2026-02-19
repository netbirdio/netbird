package proxy

import (
	"context"
	"time"
)

// Manager defines the interface for proxy operations
type Manager interface {
	Connect(ctx context.Context, proxyID, clusterAddress, ipAddress string) error
	Disconnect(ctx context.Context, proxyID string) error
	Heartbeat(ctx context.Context, proxyID string) error
	GetActiveClusterAddresses(ctx context.Context) ([]string, error)
	CleanupStale(ctx context.Context, inactivityDuration time.Duration) error
}
