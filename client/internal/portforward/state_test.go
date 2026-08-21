//go:build !js

package portforward

import (
	"context"
	"errors"
	"testing"

	"github.com/netbirdio/go-nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubDiscovery replaces both discovery entry points for the duration of a test.
func stubDiscovery(t *testing.T, gateway nat.NAT, gatewayErr error, pinhole nat.NAT, pinholeErr error) *int {
	t.Helper()

	pinholeProbes := 0
	origGateway, origPinhole := discoverNATGateway, discoverPCPPinhole
	discoverNATGateway = func(context.Context) (nat.NAT, error) { return gateway, gatewayErr }
	discoverPCPPinhole = func(context.Context) (nat.NAT, error) {
		pinholeProbes++
		return pinhole, pinholeErr
	}
	t.Cleanup(func() { discoverNATGateway, discoverPCPPinhole = origGateway, origPinhole })

	return &pinholeProbes
}

func TestDefaultDiscoverGateway(t *testing.T) {
	ipv4Gateway := &mockNAT{natType: "PCP+PCPv6"}
	ipv6Pinhole := &mockNAT{natType: "PCP"}
	otherErr := errors.New("routing table unavailable")

	t.Run("an IPv4 gateway is used as is", func(t *testing.T) {
		probes := stubDiscovery(t, ipv4Gateway, nil, nil, nil)

		got, err := defaultDiscoverGateway(context.Background())

		require.NoError(t, err)
		assert.Same(t, ipv4Gateway, got)
		assert.Zero(t, *probes, "an IPv4 gateway already carries its own pinhole")
	})

	t.Run("no IPv4 gateway still opens an IPv6 pinhole", func(t *testing.T) {
		// DiscoverGateway has no IPv4 mapping to attach a pinhole to, but the
		// router still drops inbound IPv6 until one is opened.
		probes := stubDiscovery(t, nil, nat.ErrNoNATFound, ipv6Pinhole, nil)

		got, err := defaultDiscoverGateway(context.Background())

		require.NoError(t, err)
		assert.Same(t, ipv6Pinhole, got)
		assert.Equal(t, 1, *probes)
	})

	t.Run("no gateway and no pinhole reports the original failure", func(t *testing.T) {
		stubDiscovery(t, nil, nat.ErrNoNATFound, nil, errors.New("no IPv6 route"))

		got, err := defaultDiscoverGateway(context.Background())

		assert.Nil(t, got)
		assert.ErrorIs(t, err, nat.ErrNoNATFound, "the pinhole failure must not mask why no gateway was found")
	})

	t.Run("a failure other than no-gateway is not retried as a pinhole", func(t *testing.T) {
		probes := stubDiscovery(t, nil, otherErr, ipv6Pinhole, nil)

		got, err := defaultDiscoverGateway(context.Background())

		assert.Nil(t, got)
		assert.ErrorIs(t, err, otherErr)
		assert.Zero(t, *probes, "only an absent gateway justifies falling back")
	})
}
