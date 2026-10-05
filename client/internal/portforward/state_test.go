//go:build !js

package portforward

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netbirdio/go-nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubDiscovery replaces both discovery entry points for the duration of a
// test. gatewayDelay simulates gateway discovery spending everything it is
// given before reporting that it found nothing.
func stubDiscovery(t *testing.T, gateway nat.NAT, gatewayErr error, gatewayDelay time.Duration, pinhole nat.NAT, pinholeErr error) {
	t.Helper()

	origGateway, origPinhole := discoverNATGateway, discoverPCPPinhole
	discoverNATGateway = func(ctx context.Context) (nat.NAT, error) {
		if gatewayDelay > 0 {
			select {
			case <-time.After(gatewayDelay):
			case <-ctx.Done():
			}
		}
		return gateway, gatewayErr
	}
	discoverPCPPinhole = func(ctx context.Context) (nat.NAT, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return pinhole, pinholeErr
	}

	t.Cleanup(func() { discoverNATGateway, discoverPCPPinhole = origGateway, origPinhole })
}

func TestDefaultDiscoverGateway(t *testing.T) {
	ipv4Gateway := &mockNAT{natType: "PCP+PCPv6"}
	ipv6Pinhole := &mockNAT{natType: "PCP"}
	otherErr := errors.New("routing table unavailable")

	t.Run("an IPv4 gateway is used as is", func(t *testing.T) {
		stubDiscovery(t, ipv4Gateway, nil, 0, ipv6Pinhole, nil)

		got, err := defaultDiscoverGateway(context.Background())

		require.NoError(t, err)
		assert.Same(t, ipv4Gateway, got)
	})

	t.Run("no IPv4 gateway still opens an IPv6 pinhole", func(t *testing.T) {
		stubDiscovery(t, nil, nat.ErrNoNATFound, 0, ipv6Pinhole, nil)

		got, err := defaultDiscoverGateway(context.Background())

		require.NoError(t, err)
		assert.Same(t, ipv6Pinhole, got)
	})

	t.Run("no gateway and no pinhole reports the original failure", func(t *testing.T) {
		stubDiscovery(t, nil, nat.ErrNoNATFound, 0, nil, errors.New("no IPv6 route"))

		got, err := defaultDiscoverGateway(context.Background())

		assert.Nil(t, got)
		assert.ErrorIs(t, err, nat.ErrNoNATFound, "the pinhole failure must not mask why no gateway was found")
	})

	t.Run("a failure other than no-gateway is reported as is", func(t *testing.T) {
		stubDiscovery(t, nil, otherErr, 0, ipv6Pinhole, nil)

		got, err := defaultDiscoverGateway(context.Background())

		assert.Nil(t, got)
		assert.ErrorIs(t, err, otherErr)
	})

	t.Run("the pinhole survives gateway discovery using its whole budget", func(t *testing.T) {
		// On one shared context the probe would start already expired, which is
		// how this failed against a real gateway.
		reserve := 50 * time.Millisecond
		origReserve := pinholeDiscoveryTimeout
		pinholeDiscoveryTimeout = reserve
		t.Cleanup(func() { pinholeDiscoveryTimeout = origReserve })

		budget := 4 * reserve
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()

		stubDiscovery(t, nil, nat.ErrNoNATFound, budget, ipv6Pinhole, nil)

		got, err := defaultDiscoverGateway(ctx)

		require.NoError(t, err)
		assert.Same(t, ipv6Pinhole, got)
	})
}

func TestReserveForPinhole(t *testing.T) {
	origReserve := pinholeDiscoveryTimeout
	pinholeDiscoveryTimeout = time.Second
	t.Cleanup(func() { pinholeDiscoveryTimeout = origReserve })

	t.Run("a budget is divided", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gatewayCtx, cancelGateway := reserveForPinhole(ctx)
		defer cancelGateway()

		deadline, ok := gatewayCtx.Deadline()
		require.True(t, ok)
		assert.InDelta(t, 9*time.Second, time.Until(deadline), float64(500*time.Millisecond))
	})

	t.Run("a budget too small to divide is left whole", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		gatewayCtx, cancelGateway := reserveForPinhole(ctx)
		defer cancelGateway()

		deadline, ok := gatewayCtx.Deadline()
		require.True(t, ok)
		assert.InDelta(t, 500*time.Millisecond, time.Until(deadline), float64(100*time.Millisecond))
	})

	t.Run("no deadline stays unbounded", func(t *testing.T) {
		gatewayCtx, cancelGateway := reserveForPinhole(context.Background())
		defer cancelGateway()

		_, ok := gatewayCtx.Deadline()
		assert.False(t, ok)
	})
}
