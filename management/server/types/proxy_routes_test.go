package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyRouteSet_CIDROnly(t *testing.T) {
	s := NewProxyRouteSet()
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.0.0.0/8", "172.16.0.0/12"},
	})
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"192.168.0.0/16"},
	})

	routes := s.Routes()
	require.Len(t, routes, 3)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), routes[0])
	assert.Equal(t, netip.MustParsePrefix("172.16.0.0/12"), routes[1])
	assert.Equal(t, netip.MustParsePrefix("192.168.0.0/16"), routes[2])
}

func TestProxyRouteSet_DomainOnlyForceCatchAll(t *testing.T) {
	s := NewProxyRouteSet()
	s.AddFromRule(&InspectionPolicyRule{
		Domains: []string{"*.gambling.com"},
	})
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.0.0.0/8"},
	})

	routes := s.Routes()
	require.Len(t, routes, 1)
	assert.Equal(t, netip.MustParsePrefix("0.0.0.0/0"), routes[0])
}

func TestProxyRouteSet_EmptyDestinationForceCatchAll(t *testing.T) {
	s := NewProxyRouteSet()
	s.AddFromRule(&InspectionPolicyRule{
		Action:  "block",
		// No domains, no networks: match all traffic
	})

	routes := s.Routes()
	require.Len(t, routes, 1)
	assert.Equal(t, netip.MustParsePrefix("0.0.0.0/0"), routes[0])
}

func TestProxyRouteSet_DeduplicateSubsets(t *testing.T) {
	s := NewProxyRouteSet()
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.0.0.0/8"},
	})
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.1.0.0/16"}, // subset of 10.0.0.0/8
	})
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.1.2.0/24"}, // subset of both
	})

	routes := s.Routes()
	require.Len(t, routes, 1)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), routes[0])
}

func TestProxyRouteSet_DuplicateCIDRs(t *testing.T) {
	s := NewProxyRouteSet()
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.0.0.0/8"},
	})
	s.AddFromRule(&InspectionPolicyRule{
		Networks: []string{"10.0.0.0/8"}, // duplicate
	})

	routes := s.Routes()
	require.Len(t, routes, 1)
}
