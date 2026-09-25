package client

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

func TestParseRelayedSwitchPolicy(t *testing.T) {
	testCases := []struct {
		raw  string
		want relayedSwitchPolicy
	}{
		{raw: "", want: relayedSwitchPolicy{delay: defaultRelayedSwitchDelay}},
		{raw: "  ", want: relayedSwitchPolicy{delay: defaultRelayedSwitchDelay}},
		{raw: "0", want: relayedSwitchPolicy{}},
		{raw: "10s", want: relayedSwitchPolicy{delay: 10 * time.Second}},
		{raw: " 2m ", want: relayedSwitchPolicy{delay: 2 * time.Minute}},
		{raw: "never", want: relayedSwitchPolicy{never: true}},
		{raw: "NEVER", want: relayedSwitchPolicy{never: true}},
		// unrecognised values keep the default rather than guessing
		{raw: "-5s", want: relayedSwitchPolicy{delay: defaultRelayedSwitchDelay}},
		{raw: "soon", want: relayedSwitchPolicy{delay: defaultRelayedSwitchDelay}},
		{raw: "30", want: relayedSwitchPolicy{delay: defaultRelayedSwitchDelay}},
	}

	for _, tc := range testCases {
		t.Run(tc.raw, func(t *testing.T) {
			assert.Equal(t, tc.want, parseRelayedSwitchPolicy(tc.raw), "policy parsed from %q", tc.raw)
		})
	}
}

// newRelayedTestWatcher is a watcher over two equal-metric routes, currently on
// route1, for the given policy.
func newRelayedTestWatcher(t *testing.T, policy relayedSwitchPolicy) *Watcher {
	t.Helper()

	w := newTestWatcher(t, time.Time{})
	w.relayedSwitch = policy
	t.Cleanup(func() {
		if w.relayedHold != nil {
			w.relayedHold.Stop()
		}
	})
	return w
}

// degrade walks the current routing peer route1 from direct to relayed, the way
// it is seen when a direct connection carrying the route drops to relay.
func degrade(t *testing.T, w *Watcher) {
	t.Helper()

	chosen, _ := w.getBestRouteFromStatuses(currentDirect)
	require.Equal(t, route.ID("route1"), chosen, "route1 must carry the route while direct")

	chosen, _ = w.getBestRouteFromStatuses(currentRelayed)
	require.Equal(t, route.ID("route1"), chosen, "a routing peer that just dropped to relay must be kept")
	require.False(t, w.degradedSince.IsZero(), "the drop to relay must be recorded")
}

var (
	// route1 is relayed, route2 is an equivalent peer with a direct connection
	currentRelayed = map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, relayed: true, latency: 50 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 60 * time.Millisecond},
	}
	currentDirect = map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 50 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 60 * time.Millisecond},
	}
)

func TestDegradedRoutingPeerIsKeptDuringDelay(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{delay: 30 * time.Second})

	degrade(t, w)
	require.NotNil(t, w.relayedHold, "the pending switch must arm a timer so it is applied when due")

	// the direct connection comes back within the delay: nothing moved, and the
	// degraded period ends
	chosen, _ := w.getBestRouteFromStatuses(currentDirect)
	assert.Equal(t, route.ID("route1"), chosen, "the recovered routing peer must stay chosen")
	assert.True(t, w.degradedSince.IsZero(), "the degraded period must end once the peer is direct again")
}

func TestDegradedRoutingPeerIsReplacedAfterDelay(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{delay: 30 * time.Second})

	degrade(t, w)
	w.degradedSince = w.degradedSince.Add(-31 * time.Second)

	chosen, _ := w.getBestRouteFromStatuses(currentRelayed)
	assert.Equal(t, route.ID("route2"), chosen, "a routing peer relayed for longer than the delay must give way to a direct one")
	assert.Equal(t, switchReasonDirect, w.switchReason, "the switch reason must name the relayed connection")
}

// A routing peer that was relayed when it was chosen is not degraded: when an
// equivalent direct peer shows up the route must upgrade at once instead of
// staying on the slower path for the delay.
func TestRelayedRoutingPeerUpgradesAtOnce(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{never: true})

	// route1 was chosen while relayed and route2 was still connecting
	chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, relayed: true},
		"route2": {status: peer.StatusConnecting},
	})
	require.Equal(t, route.ID("route1"), chosen)
	require.True(t, w.degradedSince.IsZero(), "a peer relayed from the start is not degraded")

	chosen, _ = w.getBestRouteFromStatuses(currentRelayed)
	assert.Equal(t, route.ID("route2"), chosen, "a direct peer must take over from one that was relayed all along")
	assert.Equal(t, switchReasonDirect, w.switchReason)
	assert.Nil(t, w.relayedHold, "an upgrade must not schedule anything")
}

// An idle routing peer woken by traffic whose relay connection comes up before
// the direct one was never direct: it is not degraded, and must give way to an
// equivalent direct peer at once.
func TestIdleRoutingPeerWokenOverRelayUpgradesAtOnce(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{never: true})

	chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusIdle},
		"route2": {status: peer.StatusIdle},
	})
	require.Equal(t, route.ID("route1"), chosen)

	chosen, _ = w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, relayed: true},
		"route2": {status: peer.StatusConnecting},
	})
	require.Equal(t, route.ID("route1"), chosen)
	require.True(t, w.degradedSince.IsZero(), "waking up over relay is not a drop from direct")

	chosen, _ = w.getBestRouteFromStatuses(currentRelayed)
	assert.Equal(t, route.ID("route2"), chosen, "a direct peer must take over from one that was never direct")
	assert.Nil(t, w.relayedHold, "an upgrade must not schedule anything")
}

// A routing peer that drops to relay again, after recovering from an earlier
// drop, is a new degradation and must be reported at info level again.
func TestRepeatedDegradationIsReportedAgain(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{delay: 30 * time.Second})

	degrade(t, w)
	require.Equal(t, route.ID("route2"), w.heldCandidate, "the first drop must be reported")

	// the first report is well within the report interval
	w.heldReported = w.heldReported.Add(-time.Minute)
	firstReport := w.heldReported

	degrade(t, w)
	assert.True(t, w.heldReported.After(firstReport), "a new drop to relay must be reported, not treated as a repeat")
}

func TestDegradedRoutingPeerNeverPolicy(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{never: true})

	degrade(t, w)
	w.degradedSince = w.degradedSince.Add(-time.Hour)

	chosen, _ := w.getBestRouteFromStatuses(currentRelayed)
	assert.Equal(t, route.ID("route1"), chosen, "with never, a degraded routing peer is kept while connected")
	assert.Nil(t, w.relayedHold, "with never there is nothing to schedule")
}

func TestDegradedRoutingPeerZeroDelaySwitchesAtOnce(t *testing.T) {
	w := newRelayedTestWatcher(t, relayedSwitchPolicy{})

	chosen, _ := w.getBestRouteFromStatuses(currentDirect)
	require.Equal(t, route.ID("route1"), chosen)

	chosen, _ = w.getBestRouteFromStatuses(currentRelayed)
	assert.Equal(t, route.ID("route2"), chosen, "a zero delay must keep the immediate switch to a direct peer")
}

// The delay only covers a candidate that is better solely by being direct. A
// better metric or a lost routing peer must move the route at once.
func TestRelayedDelayDoesNotHoldOtherSwitches(t *testing.T) {
	t.Run("better metric", func(t *testing.T) {
		w := newRelayedTestWatcher(t, relayedSwitchPolicy{never: true})
		degrade(t, w)
		w.routes["route2"].Metric = route.MaxMetric - 1

		chosen, _ := w.getBestRouteFromStatuses(currentRelayed)
		assert.Equal(t, route.ID("route2"), chosen, "a better metric must win over a degraded peer immediately")
		assert.Equal(t, switchReasonMetric, w.switchReason)
	})

	t.Run("current peer disconnected", func(t *testing.T) {
		w := newRelayedTestWatcher(t, relayedSwitchPolicy{never: true})
		degrade(t, w)

		chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnecting, relayed: true},
			"route2": {status: peer.StatusConnected, latency: 60 * time.Millisecond},
		})
		assert.Equal(t, route.ID("route2"), chosen, "a routing peer that is gone must be replaced regardless of the delay")
		assert.Equal(t, switchReasonUnavailable, w.switchReason)
	})

	t.Run("both relayed", func(t *testing.T) {
		w := newRelayedTestWatcher(t, relayedSwitchPolicy{delay: 30 * time.Second})

		chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, relayed: true},
			"route2": {status: peer.StatusConnected, relayed: true},
		})
		assert.Equal(t, route.ID("route1"), chosen, "equally relayed peers are a tie and the current one stays")
		assert.Nil(t, w.relayedHold, "a tie must not schedule a switch")
	})
}

// TestRelayedHoldTimerAppliesSwitch drives the Start loop: once the delay has
// passed, the held switch must be applied without waiting for a peer update or
// the periodic re-evaluation.
func TestRelayedHoldTimerAppliesSwitch(t *testing.T) {
	w, handler := newRecalcWatcher(t)
	w.relayedSwitch = relayedSwitchPolicy{delay: 50 * time.Millisecond}

	recorder := w.statusRecorder
	for _, key := range []string{"peer1", "peer2"} {
		require.NoError(t, recorder.AddPeer(key, key+".netbird.cloud", "100.64.0.1", ""))
	}
	require.NoError(t, recorder.UpdatePeerState(peer.State{PubKey: "peer1", ConnStatus: peer.StatusConnected, Relayed: true}))
	require.NoError(t, recorder.UpdatePeerState(peer.State{PubKey: "peer2", ConnStatus: peer.StatusConnected}))

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected},
	}))
	require.Equal(t, []string{"peer1"}, handler.added)

	// route1 drops to relay while route2 is direct: held for the delay
	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, relayed: true},
		"route2": {status: peer.StatusConnected},
	}))
	require.Equal(t, []string{"peer1"}, handler.added, "the switch must be held while the delay runs")

	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.done = make(chan struct{})
	go w.Start()
	t.Cleanup(w.Stop)

	// the loop owns the watcher state now, so observe the switch through the
	// event it publishes rather than reading its fields
	require.Eventually(t, func() bool {
		for _, e := range recorder.GetEventHistory() {
			if e.Message == "Routing peer changed" && e.Metadata["peer"] == "peer2" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "the held switch must be applied once the delay passed")
}

// A route update can keep a route's ID and hand it to a different routing peer.
// That is a switch like any other: it is reported, and the new peer is tracked
// from its own state rather than inheriting the previous peer's.
func TestRouteReassignedToDifferentPeerIsASwitch(t *testing.T) {
	w, handler := newRecalcWatcher(t)

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected},
	}))
	require.Equal(t, []string{"peer1"}, handler.added)

	reassigned := *w.routes["route1"]
	reassigned.Peer = "peer3"
	w.routes["route1"] = &reassigned

	require.NoError(t, w.recalculateRoutes(reasonRouteUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, relayed: true},
	}))
	assert.Equal(t, []string{"peer1", "peer3"}, handler.added, "the allowed IPs must move to the new routing peer")
	assert.Equal(t, "peer3", w.trackedPeer, "the new routing peer must be tracked")
	assert.False(t, w.trackedDirect, "the new routing peer is tracked from its own state")

	events := w.statusRecorder.GetEventHistory()
	require.Len(t, events, 1, "the reassignment must publish a switch event")
	assert.Equal(t, "Routing peer changed", events[0].Message)
	assert.Equal(t, "peer1", events[0].Metadata["previous_peer"])
	assert.Equal(t, "peer3", events[0].Metadata["peer"])
	assert.Equal(t, string(switchReasonRouteChanged), events[0].Metadata["reason"])
}

// Exit nodes report their own connect and disconnect events, but those carry
// no reason: the switch event is published for default routes too.
func TestDefaultRouteSwitchPublishesEvent(t *testing.T) {
	w, _ := newRecalcWatcher(t)
	for _, r := range w.routes {
		r.Network = netip.MustParsePrefix("0.0.0.0/0")
	}

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected},
	}))
	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnecting},
		"route2": {status: peer.StatusConnected},
	}))

	var switchEvents []*proto.SystemEvent
	for _, e := range w.statusRecorder.GetEventHistory() {
		if e.Message == "Routing peer changed" {
			switchEvents = append(switchEvents, e)
		}
	}
	require.Len(t, switchEvents, 1, "an exit node switch must publish a switch event")
	assert.Equal(t, string(switchReasonUnavailable), switchEvents[0].Metadata["reason"])
	assert.Empty(t, switchEvents[0].UserMessage, "the switch event must not notify the user a second time")
}

func TestRoutingPeerSwitchPublishesEvent(t *testing.T) {
	w, _ := newRecalcWatcher(t)

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 20 * time.Millisecond},
	}))
	assert.Empty(t, w.statusRecorder.GetEventHistory(), "the initial assignment is not a switch")

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnecting},
		"route2": {status: peer.StatusConnected, latency: 20 * time.Millisecond},
	}))

	events := w.statusRecorder.GetEventHistory()
	require.Len(t, events, 1, "a switch must publish exactly one event")
	assert.Equal(t, proto.SystemEvent_WARNING, events[0].Severity)
	assert.Equal(t, "Routing peer changed", events[0].Message)
	assert.Equal(t, map[string]string{
		"network":       "recording",
		"id":            "",
		"previous_peer": "peer1",
		"peer":          "peer2",
		"reason":        string(switchReasonUnavailable),
	}, events[0].Metadata, "the event must name both peers and the reason")

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnecting},
		"route2": {status: peer.StatusConnecting},
	}))

	events = w.statusRecorder.GetEventHistory()
	require.Len(t, events, 2, "losing the last routing peer must publish an event")
	assert.Equal(t, "No routing peer available", events[1].Message)
	assert.Equal(t, "peer2", events[1].Metadata["previous_peer"])
}
