package internal

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func TestCanHandleWithoutRestart(t *testing.T) {
	// The light path is available only with advanced routing and on a platform
	// that does not pin the underlay at start; everything else restarts.
	lightPath := nbnet.AdvancedRouting() && !underlayPinnedAtStart

	tests := []struct {
		name         string
		kind         networkmonitor.ChangeKind
		hasNetEvents bool
		want         bool
	}{
		{name: "unchanged underlay restarts", kind: networkmonitor.ChangeNone, hasNetEvents: true, want: false},
		{name: "no netevents manager restarts", kind: networkmonitor.ChangeGateway, hasNetEvents: false, want: false},
		{name: "address change, as with a new DHCP lease", kind: networkmonitor.ChangeAddress, hasNetEvents: true, want: lightPath},
		{name: "gateway change", kind: networkmonitor.ChangeGateway, hasNetEvents: true, want: lightPath},
		{name: "interface change, as with a cable plugged in", kind: networkmonitor.ChangeInterface, hasNetEvents: true, want: lightPath},
		{name: "wake-up keeps the restart", kind: networkmonitor.ChangeWake, hasNetEvents: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			change := networkmonitor.Change{Kind: tt.kind}
			assert.Equal(t, tt.want, canHandleWithoutRestart(change, tt.hasNetEvents), "restart decision")
		})
	}
}

func TestCanHandleWithoutRestart_DisabledByEnv(t *testing.T) {
	change := networkmonitor.Change{Kind: networkmonitor.ChangeInterface}

	t.Setenv(EnvDisableNetworkChangeRedial, "true")
	assert.False(t, canHandleWithoutRestart(change, true), "the env switch must force the restart")

	// An unparsable value keeps the default behavior instead of silently disabling it.
	t.Setenv(EnvDisableNetworkChangeRedial, "maybe")
	lightPath := nbnet.AdvancedRouting() && !underlayPinnedAtStart
	assert.Equal(t, lightPath, canHandleWithoutRestart(change, true), "an invalid value falls back to the default")
}

func TestWaitUntilReady(t *testing.T) {
	const (
		grace   = 20 * time.Millisecond
		timeout = 200 * time.Millisecond
		poll    = 5 * time.Millisecond
	)

	t.Run("control plane comes back after the grace", func(t *testing.T) {
		var calls atomic.Int32
		ready := func() bool { return calls.Add(1) >= 3 }
		assert.True(t, waitUntilReady(context.Background(), grace, timeout, poll, ready), "a recovery within the timeout must pass")
	})

	t.Run("readiness is not checked during the grace", func(t *testing.T) {
		// The sweep needs the grace to close the stale sockets; a check before
		// it would accept the old connections.
		start := time.Now()
		assert.True(t, waitUntilReady(context.Background(), grace, timeout, poll, func() bool { return true }), "always ready")
		assert.GreaterOrEqual(t, time.Since(start), grace, "the first check must come after the grace")
	})

	t.Run("control plane never comes back", func(t *testing.T) {
		start := time.Now()
		assert.False(t, waitUntilReady(context.Background(), grace, timeout, poll, func() bool { return false }), "a missing recovery must fail")
		assert.GreaterOrEqual(t, time.Since(start), timeout, "the timeout counts from the call")
	})

	t.Run("cancelled by a newer change or by the engine stop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.False(t, waitUntilReady(ctx, grace, timeout, poll, func() bool { return true }), "a cancelled watch must not report recovery")
	})
}

func TestRecoveryWatchReplace(t *testing.T) {
	var w recoveryWatch
	first := w.replace(context.Background())
	second := w.replace(context.Background())

	assert.Error(t, first.Err(), "the previous watch is cancelled by a newer change")
	assert.NoError(t, second.Err(), "the latest watch stays active")

	w.stop()
	assert.Error(t, second.Err(), "stop cancels the latest watch")
	w.stop()
}
