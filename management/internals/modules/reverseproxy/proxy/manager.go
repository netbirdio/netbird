package proxy

//go:generate go run github.com/golang/mock/mockgen -package proxy -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// Manager defines the interface for proxy operations
type Manager interface {
	Connect(ctx context.Context, proxyID, sessionID, clusterAddress, ipAddress string, capabilities *Capabilities) (*Proxy, error)
	Disconnect(ctx context.Context, proxyID, sessionID string) error
	Heartbeat(ctx context.Context, p *Proxy) error
	GetActiveClusterAddresses(ctx context.Context) ([]string, error)
	GetActiveClusters(ctx context.Context) ([]Cluster, error)
	ClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	ClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
	ClusterSupportsCrowdSec(ctx context.Context, clusterAddr string) *bool
	CleanupStale(ctx context.Context, inactivityDuration time.Duration) error
}

// OIDCValidationConfig contains the OIDC configuration needed for token validation.
type OIDCValidationConfig struct {
	Issuer             string
	Audiences          []string
	KeysLocation       string
	MaxTokenAgeSeconds int64
}

// Controller is responsible for managing proxy clusters and routing service updates.
type Controller interface {
	SendServiceUpdateToCluster(ctx context.Context, accountID string, update *proto.ProxyMapping, clusterAddr string)
	GetOIDCValidationConfig() OIDCValidationConfig
	RegisterProxyToCluster(ctx context.Context, clusterAddr, proxyID string) error
	UnregisterProxyFromCluster(ctx context.Context, clusterAddr, proxyID string) error
	GetProxiesForCluster(clusterAddr string) []string
}
