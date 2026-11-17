package net

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDialAttemptTimeoutSplitsBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	got := dialAttemptTimeout(ctx, 3)
	assert.GreaterOrEqual(t, got, minDialAttemptTimeout, "split timeout should respect minDialAttemptTimeout")
	assert.LessOrEqual(t, got, maxDialAttemptTimeout, "split timeout should respect maxDialAttemptTimeout")
	assert.InDelta(t, float64(4*time.Second), float64(got), float64(50*time.Millisecond),
		"12s budget across 3 attempts should be ~4s each")
}

func TestDialAttemptTimeoutRespectsShortDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	got := dialAttemptTimeout(ctx, 2)
	require.Greater(t, got, time.Duration(0), "short-deadline split timeout should stay positive")
	assert.LessOrEqual(t, got, 1500*time.Millisecond, "split timeout should not exceed remaining deadline")
}

func TestDialAttemptTimeoutWithoutDeadline(t *testing.T) {
	got := dialAttemptTimeout(context.Background(), 2)
	assert.Equal(t, maxDialAttemptTimeout, got, "no deadline should use maxDialAttemptTimeout")
}

func TestSelectionForInterface(t *testing.T) {
	iface := &net.Interface{Index: 7, Name: "Wi-Fi"}

	v4 := netip.MustParseAddr("1.2.3.4")
	sel4 := selectionForInterface(v4, iface)
	require.NotNil(t, sel4.iface4, "IPv4 selection should set iface4")
	assert.Equal(t, 7, sel4.iface4.Index, "IPv4 selection should keep interface index")
	assert.Nil(t, sel4.iface6, "IPv4 selection should not set iface6")

	v6 := netip.MustParseAddr("2001:db8::1")
	sel6 := selectionForInterface(v6, iface)
	require.NotNil(t, sel6.iface6, "IPv6 selection should set iface6")
	assert.Equal(t, 7, sel6.iface6.Index, "IPv6 selection should keep interface index")
	require.NotNil(t, sel6.iface4, "IPv6 dual-stack selection should also set iface4")
}
