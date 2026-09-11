//go:build linux

package nftables

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
)

// TestExternalChainMonitorRootIntegration verifies that adding a new chain
// in an external (non-netbird) filter table triggers the reconciler.
// Requires CAP_NET_ADMIN; skip otherwise.
func TestExternalChainMonitorRootIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}

	calls := make(chan struct{}, 8)
	var count atomic.Int32
	rec := &countingReconciler{calls: calls, count: &count}

	m := newExternalChainMonitor(rec)
	m.start()
	t.Cleanup(m.stop)

	// Give the netlink subscription a moment to register.
	time.Sleep(200 * time.Millisecond)

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Name:   "nbmon_integration_test",
		Family: nftables.TableFamilyINet,
	})
	t.Cleanup(func() {
		cleanup := &nftables.Conn{}
		cleanup.DelTable(table)
		_ = cleanup.Flush()
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     "filter_INPUT",
		Table:    table,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	})
	_ = chain
	require.NoError(t, conn.Flush(), "create external test chain")

	select {
	case <-calls:
		// success
	case <-time.After(3 * time.Second):
		t.Fatalf("reconcile was not invoked after creating an external chain")
	}
	require.GreaterOrEqual(t, count.Load(), int32(1))
}

type countingReconciler struct {
	calls chan struct{}
	count *atomic.Int32
}

func (c *countingReconciler) reconcileExternalChains() error {
	c.count.Add(1)
	select {
	case c.calls <- struct{}{}:
	default:
	}
	return nil
}
