package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEndpoint_PrefersZoneOverCluster locks the decoupling: when a Zone is set
// the hostname must NOT embed the serving cluster, so moving a tenant between
// proxies never changes their address.
func TestEndpoint_PrefersZoneOverCluster(t *testing.T) {
	s := &Settings{Subdomain: "brave-otter", Cluster: "eu.proxy.netbird.io", Zone: "gateway.netbird.ai"}
	assert.Equal(t, "brave-otter.gateway.netbird.ai", s.Endpoint())
}

// TestEndpoint_FallsBackToClusterWhenZoneEmpty is the compatibility guarantee:
// existing rows (and every self-hosted deployment, which sets no zone) keep
// exactly the address they have today.
func TestEndpoint_FallsBackToClusterWhenZoneEmpty(t *testing.T) {
	s := &Settings{Subdomain: "otter", Cluster: "eu.proxy.netbird.io"}
	assert.Equal(t, "otter.eu.proxy.netbird.io", s.Endpoint())
}

// TestToAPIResponse_ExposesZoneAndDerivedEndpoint — the dashboard renders
// Endpoint verbatim, so it must reflect the zone.
func TestToAPIResponse_ExposesZoneAndDerivedEndpoint(t *testing.T) {
	s := &Settings{Subdomain: "brave-otter", Cluster: "eu.proxy.netbird.io", Zone: "gateway.netbird.ai"}
	resp := s.ToAPIResponse()
	assert.Equal(t, "brave-otter.gateway.netbird.ai", resp.Endpoint)
}
