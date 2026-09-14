package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
)

func TestIsMonitoredFamily(t *testing.T) {
	tests := []struct {
		family nftables.TableFamily
		want   bool
	}{
		{nftables.TableFamilyIPv4, true},
		{nftables.TableFamilyIPv6, true},
		{nftables.TableFamilyINet, true},
		{nftables.TableFamilyARP, false},
		{nftables.TableFamilyBridge, false},
		{nftables.TableFamilyNetdev, false},
		{nftables.TableFamilyUnspecified, false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, isMonitoredFamily(tc.family), "family=%d", tc.family)
	}
}

func TestIsRelevantMonitorEvent(t *testing.T) {
	inetTable := &nftables.Table{Name: "firewalld", Family: nftables.TableFamilyINet}
	ipTable := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	arpTable := &nftables.Table{Name: "arp", Family: nftables.TableFamilyARP}

	tests := []struct {
		name string
		ev   *nftables.MonitorEvent
		want bool
	}{
		{
			name: "new chain in inet firewalld",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeNewChain,
				Data: &nftables.Chain{Name: "filter_INPUT", Table: inetTable},
			},
			want: true,
		},
		{
			name: "new chain in ip filter",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeNewChain,
				Data: &nftables.Chain{Name: "INPUT", Table: ipTable},
			},
			want: true,
		},
		{
			name: "new chain in unwatched arp family",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeNewChain,
				Data: &nftables.Chain{Name: "x", Table: arpTable},
			},
			want: false,
		},
		{
			name: "new table inet",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeNewTable,
				Data: inetTable,
			},
			want: true,
		},
		{
			name: "del chain (we only act on new)",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeDelChain,
				Data: &nftables.Chain{Name: "filter_INPUT", Table: inetTable},
			},
			want: false,
		},
		{
			name: "chain with nil table",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeNewChain,
				Data: &nftables.Chain{Name: "x"},
			},
			want: false,
		},
		{
			name: "nil data",
			ev: &nftables.MonitorEvent{
				Type: nftables.MonitorEventTypeNewChain,
				Data: (*nftables.Chain)(nil),
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isRelevantMonitorEvent(tc.ev))
		})
	}
}

// fakeReconciler records reconcile invocations for debounce tests.
type fakeReconciler struct {
	calls chan struct{}
}

func (f *fakeReconciler) reconcileExternalChains() error {
	f.calls <- struct{}{}
	return nil
}

func TestExternalChainMonitorStopWithoutStart(t *testing.T) {
	m := newExternalChainMonitor(&fakeReconciler{calls: make(chan struct{}, 1)})
	// Must not panic or block.
	m.stop()
}

func TestExternalChainMonitorDoubleStart(t *testing.T) {
	// start() twice should be a no-op; stop() cleans up once.
	// We avoid exercising the netlink watch loop here because it needs root.
	m := newExternalChainMonitor(&fakeReconciler{calls: make(chan struct{}, 1)})

	// Replace run with a stub that just waits for cancel, so start() stays
	// deterministic without opening a netlink socket.
	origDone := make(chan struct{})
	m.done = origDone
	m.cancel = func() { close(origDone) }

	// Second start should be a no-op (cancel already set).
	m.start()
	assert.NotNil(t, m.cancel)

	m.stop()
	assert.Nil(t, m.cancel)
	assert.Nil(t, m.done)
}
