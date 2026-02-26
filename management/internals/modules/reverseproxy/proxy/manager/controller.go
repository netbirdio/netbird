package manager

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// GRPCController is a concrete implementation that manages proxy clusters and sends updates directly via gRPC.
type GRPCController struct {
	proxyGRPCServer *nbgrpc.ProxyServiceServer
	// Map of cluster address -> set of proxy IDs
	clusterProxies sync.Map
	metrics        *metrics
}

// NewGRPCController creates a new GRPCController.
func NewGRPCController(proxyGRPCServer *nbgrpc.ProxyServiceServer, meter metric.Meter) (*GRPCController, error) {
	m, err := newMetrics(meter)
	if err != nil {
		return nil, err
	}

	return &GRPCController{
		proxyGRPCServer: proxyGRPCServer,
		metrics:         m,
	}, nil
}

// SendServiceUpdateToCluster sends a service update to a specific proxy cluster.
func (c *GRPCController) SendServiceUpdateToCluster(ctx context.Context, accountID string, update *proto.ProxyMapping, clusterAddr string) {
	c.proxyGRPCServer.SendServiceUpdateToCluster(ctx, update, clusterAddr)
	c.metrics.IncrementServiceUpdateSendCount(clusterAddr)
}

// GetOIDCValidationConfig returns the OIDC validation configuration from the gRPC server.
func (c *GRPCController) GetOIDCValidationConfig() proxy.OIDCValidationConfig {
	return c.proxyGRPCServer.GetOIDCValidationConfig()
}

// RegisterProxyToCluster registers a proxy to a specific cluster for routing.
func (c *GRPCController) RegisterProxyToCluster(ctx context.Context, clusterAddr, proxyID string) error {
	if clusterAddr == "" {
		return nil
	}
	proxySet, _ := c.clusterProxies.LoadOrStore(clusterAddr, &sync.Map{})
	proxySet.(*sync.Map).Store(proxyID, struct{}{})
	log.WithContext(ctx).Debugf("Registered proxy %s to cluster %s", proxyID, clusterAddr)

	c.metrics.IncrementProxyConnectionCount(clusterAddr)

	return nil
}

// UnregisterProxyFromCluster removes a proxy from a cluster.
func (c *GRPCController) UnregisterProxyFromCluster(ctx context.Context, clusterAddr, proxyID string) error {
	if clusterAddr == "" {
		return nil
	}
	if proxySet, ok := c.clusterProxies.Load(clusterAddr); ok {
		proxySet.(*sync.Map).Delete(proxyID)
		log.WithContext(ctx).Debugf("Unregistered proxy %s from cluster %s", proxyID, clusterAddr)

		c.metrics.DecrementProxyConnectionCount(clusterAddr)
	}
	return nil
}

// GetProxiesForCluster returns all proxy IDs registered for a specific cluster.
func (c *GRPCController) GetProxiesForCluster(clusterAddr string) []string {
	proxySet, ok := c.clusterProxies.Load(clusterAddr)
	if !ok {
		return nil
	}

	var proxies []string
	proxySet.(*sync.Map).Range(func(key, _ interface{}) bool {
		proxies = append(proxies, key.(string))
		return true
	})
	return proxies
}
