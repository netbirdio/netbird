package internal

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/netevents"
)

// loopRun records what the loop did with a scripted series of changes.
type loopRun struct {
	baselines []networkmonitor.NextHops
	armed     int
	stopped   int
	restarted int
	redialed  int
}

func runLoop(t *testing.T, mgr *netevents.Manager, script []networkmonitor.Change, actions map[networkmonitor.ChangeKind]underlayAction) *loopRun {
	t.Helper()
	r := &loopRun{}
	next := 0
	loop := underlayLoop{
		listen: func(_ context.Context, baseline networkmonitor.NextHops) (networkmonitor.Change, error) {
			r.baselines = append(r.baselines, baseline)
			if next == len(script) {
				return networkmonitor.Change{}, context.Canceled
			}
			next++
			return script[next-1], nil
		},
		decide:       func(c networkmonitor.Change) underlayAction { return actions[c.Kind] },
		redial:       func(networkmonitor.Change) bool { r.redialed++; return true },
		restart:      func() { r.restarted++ },
		armWatch:     func() { r.armed++ },
		stopWatch:    func() { r.stopped++ },
		availability: networkAvailability{mgr: mgr},
	}
	loop.run(context.Background())
	return r
}

func snapshot(gw string) networkmonitor.NextHops {
	return networkmonitor.NextHops{V4: systemops.Nexthop{IP: netip.MustParseAddr(gw), Intf: &net.Interface{Index: 2, Name: "eth0"}}}
}

var testActions = map[networkmonitor.ChangeKind]underlayAction{
	networkmonitor.ChangeNone:      actionNone,
	networkmonitor.ChangeGateway:   actionRedial,
	networkmonitor.ChangeOffline:   actionWait,
	networkmonitor.ChangeInterface: actionRedial,
	networkmonitor.ChangeWake:      actionRestart,
}

// Offline then back on the same network: going offline swept the control
// connections, so their return must be watched even though the snapshot did
// not move.
func TestUnderlayLoopWatchesTheReturnFromOffline(t *testing.T) {
	home := snapshot("192.168.1.1")
	mgr := netevents.NewManager(peer.NewRecorder(""))
	r := runLoop(t, mgr, []networkmonitor.Change{
		{Kind: networkmonitor.ChangeOffline, Before: home},
		{Kind: networkmonitor.ChangeNone, Before: home, After: home},
	}, testActions)

	require.Len(t, r.baselines, 3, "listen rounds")
	assert.Equal(t, home, r.baselines[1], "offline keeps the pre-loss snapshot as the baseline")
	assert.Equal(t, 1, r.armed, "the safety net watches the return from offline")
	assert.Equal(t, 0, r.restarted, "no restart")
	assert.True(t, mgr.IsOnline(), "the manager is back online")
}

func TestUnderlayLoopSequences(t *testing.T) {
	home, cafe := snapshot("192.168.1.1"), snapshot("10.0.0.1")

	t.Run("nothing moved: no safety net", func(t *testing.T) {
		r := runLoop(t, nil, []networkmonitor.Change{{Kind: networkmonitor.ChangeNone, Before: home, After: home}}, testActions)
		assert.Equal(t, 0, r.armed, "no redial, nothing to watch")
	})

	t.Run("redial arms the safety net and moves the baseline", func(t *testing.T) {
		r := runLoop(t, nil, []networkmonitor.Change{{Kind: networkmonitor.ChangeGateway, Before: home, After: cafe}}, testActions)
		assert.Equal(t, 1, r.redialed, "redial")
		assert.Equal(t, 1, r.armed, "safety net armed")
		assert.Equal(t, cafe, r.baselines[1], "the new network becomes the baseline")
	})

	t.Run("offline stops a running safety net", func(t *testing.T) {
		r := runLoop(t, nil, []networkmonitor.Change{
			{Kind: networkmonitor.ChangeGateway, Before: home, After: cafe},
			{Kind: networkmonitor.ChangeOffline, Before: cafe},
		}, testActions)
		assert.GreaterOrEqual(t, r.stopped, 1, "offline stops the safety net")
		assert.Equal(t, 0, r.restarted, "no restart")
	})

	t.Run("restart ends the loop", func(t *testing.T) {
		r := runLoop(t, nil, []networkmonitor.Change{
			{Kind: networkmonitor.ChangeWake, Before: home, After: home},
			{Kind: networkmonitor.ChangeGateway, Before: home, After: cafe},
		}, testActions)
		assert.Equal(t, 1, r.restarted, "restart")
		assert.Equal(t, 0, r.redialed, "nothing after the restart")
	})
}
