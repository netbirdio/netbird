package manager

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// GRPCProxyController is a concrete implementation that manages proxy clusters and sends updates directly via gRPC.
type GRPCProxyController struct {
	proxyGRPCServer *nbgrpc.ProxyServiceServer
	// Map of cluster address -> set of proxy IDs
	clusterProxies sync.Map
}

// NewGRPCProxyController creates a new GRPCProxyController.
func NewGRPCProxyController(proxyGRPCServer *nbgrpc.ProxyServiceServer) *GRPCProxyController {
	return &GRPCProxyController{
		proxyGRPCServer: proxyGRPCServer,
	}
}

// SendServiceUpdateToCluster sends a service update to a specific proxy cluster.
func (c *GRPCProxyController) SendServiceUpdateToCluster(ctx context.Context, accountID string, update *proto.ProxyMapping, clusterAddr string) {
	c.proxyGRPCServer.SendServiceUpdateToCluster(ctx, update, clusterAddr)
}

// GetOIDCValidationConfig returns the OIDC validation configuration from the gRPC server.
func (c *GRPCProxyController) GetOIDCValidationConfig() rpservice.OIDCValidationConfig {
	return c.proxyGRPCServer.GetOIDCValidationConfig()
}

// RegisterProxyToCluster registers a proxy to a specific cluster for routing.
func (c *GRPCProxyController) RegisterProxyToCluster(ctx context.Context, clusterAddr, proxyID string) error {
	if clusterAddr == "" {
		return nil
	}
	proxySet, _ := c.clusterProxies.LoadOrStore(clusterAddr, &sync.Map{})
	proxySet.(*sync.Map).Store(proxyID, struct{}{})
	log.WithContext(ctx).Debugf("Registered proxy %s to cluster %s", proxyID, clusterAddr)
	return nil
}

// UnregisterProxyFromCluster removes a proxy from a cluster.
func (c *GRPCProxyController) UnregisterProxyFromCluster(ctx context.Context, clusterAddr, proxyID string) error {
	if clusterAddr == "" {
		return nil
	}
	if proxySet, ok := c.clusterProxies.Load(clusterAddr); ok {
		proxySet.(*sync.Map).Delete(proxyID)
		log.WithContext(ctx).Debugf("Unregistered proxy %s from cluster %s", proxyID, clusterAddr)
	}
	return nil
}

// GetProxiesForCluster returns all proxy IDs registered for a specific cluster.
func (c *GRPCProxyController) GetProxiesForCluster(clusterAddr string) []string {
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
