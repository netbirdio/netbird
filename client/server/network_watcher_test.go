package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/netevents"
	"github.com/netbirdio/netbird/client/netevents/watcher"
	"github.com/netbirdio/netbird/client/proto"
)

type dummyRecorder struct{}

func (d *dummyRecorder) SetNetworkAvailable(_ bool) {}

func TestServer_OnNetworkEvent_UnderlyingVPN(t *testing.T) {
	rec := &dummyRecorder{}
	netMgr := netevents.NewManager(rec)

	s := &Server{
		rootCtx: context.Background(),
		netMgr:  netMgr,
	}

	assert.True(t, s.netMgr.IsOnline(), "should start online")

	// Disconnect underlying VPN
	s.OnNetworkEvent(watcher.Event{
		Kind:          watcher.EventUnderlyingVPNDisconnected,
		Name:          "corporate-vpn",
		Reason:        "user disconnected",
		UserInitiated: true,
	})

	assert.False(t, s.netMgr.IsOnline(), "should be offline after underlying VPN disconnect")

	// Reconnect underlying VPN
	s.OnNetworkEvent(watcher.Event{
		Kind:          watcher.EventUnderlyingVPNConnected,
		Name:          "corporate-vpn",
		Reason:        "connected",
		UserInitiated: false,
	})

	assert.True(t, s.netMgr.IsOnline(), "should be online after underlying VPN reconnect")
}

func TestServer_OnNetworkEvent_HostNetwork(t *testing.T) {
	rec := &dummyRecorder{}
	netMgr := netevents.NewManager(rec)

	s := &Server{
		rootCtx: context.Background(),
		netMgr:  netMgr,
	}

	assert.True(t, s.netMgr.IsOnline(), "should start online")

	// Disconnect host network
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventNetworkDisconnected,
		Reason: "wifi link down",
	})

	assert.False(t, s.netMgr.IsOnline(), "should be offline after host network disconnect")

	// Reconnect host network
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventNetworkConnected,
		Reason: "wifi link up",
	})

	assert.True(t, s.netMgr.IsOnline(), "should be online after host network reconnect")
}

func TestServer_OnNetworkEvent_NetBirdInterfaceUserDisconnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = internal.CtxInitState(ctx)
	internal.CtxGetState(ctx).Set(internal.StatusConnected)

	rec := &dummyRecorder{}
	netMgr := netevents.NewManager(rec)

	downCalled := make(chan struct{}, 1)
	s := &Server{
		rootCtx:             ctx,
		netMgr:              netMgr,
		clientRunning:       true,
		networkWatcherIface: "wt0",
		downFn: func(_ context.Context, _ *proto.DownRequest) (*proto.DownResponse, error) {
			select {
			case downCalled <- struct{}{}:
			default:
			}
			return &proto.DownResponse{}, nil
		},
	}

	s.OnNetworkEvent(watcher.Event{
		Kind:          watcher.EventNetBirdInterfaceDisconnected,
		Name:          "wt0",
		Reason:        "user disconnected via nmcli",
		UserInitiated: true,
	})

	select {
	case <-downCalled:
		// Succeeded: Down was invoked
	case <-time.After(2 * time.Second):
		t.Fatal("expected Down to be invoked on user-initiated disconnect")
	}
}

func TestServer_OnNetworkEvent_IgnoredWhenNotConnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = internal.CtxInitState(ctx)
	internal.CtxGetState(ctx).Set(internal.StatusIdle)

	rec := &dummyRecorder{}
	netMgr := netevents.NewManager(rec)

	downCalled := make(chan struct{}, 1)
	s := &Server{
		rootCtx:             ctx,
		netMgr:              netMgr,
		clientRunning:       true,
		networkWatcherIface: "wt0",
		downFn: func(_ context.Context, _ *proto.DownRequest) (*proto.DownResponse, error) {
			select {
			case downCalled <- struct{}{}:
			default:
			}
			return &proto.DownResponse{}, nil
		},
	}

	// Should be ignored because status is Idle, not Connected
	s.OnNetworkEvent(watcher.Event{
		Kind:          watcher.EventNetBirdInterfaceDisconnected,
		Name:          "wt0",
		Reason:        "link down during startup",
		UserInitiated: false,
	})

	select {
	case <-downCalled:
		t.Fatal("expected idle disconnect to be ignored, but Down was invoked")
	case <-time.After(100 * time.Millisecond):
		// Succeeded: Down was not called
	}
}

func TestServer_OnNetworkEvent_AggregateAvailability(t *testing.T) {
	rec := &dummyRecorder{}
	netMgr := netevents.NewManager(rec)

	s := &Server{
		rootCtx: context.Background(),
		netMgr:  netMgr,
	}

	assert.True(t, s.netMgr.IsOnline(), "should start online")

	// 1. Host network disconnects -> offline
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventNetworkDisconnected,
		Reason: "wifi link down",
	})
	assert.False(t, s.netMgr.IsOnline(), "should be offline after host network disconnect")

	// 2. Underlying VPN connects while host network is still down -> must remain offline!
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventUnderlyingVPNConnected,
		Name:   "corp-vpn",
		Reason: "vpn connected",
	})
	assert.False(t, s.netMgr.IsOnline(), "should remain offline when host network is down even if VPN reports connected")

	// 3. Host network connects -> now both are online -> online!
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventNetworkConnected,
		Reason: "wifi link up",
	})
	assert.True(t, s.netMgr.IsOnline(), "should be online when both host network and VPN are up")

	// 4. Underlying VPN disconnects -> offline
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventUnderlyingVPNDisconnected,
		Name:   "corp-vpn",
		Reason: "vpn dropped",
	})
	assert.False(t, s.netMgr.IsOnline(), "should be offline when underlying VPN drops")

	// 5. Host network reports connected -> must remain offline because VPN is still down!
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventNetworkConnected,
		Reason: "wifi roaming",
	})
	assert.False(t, s.netMgr.IsOnline(), "should remain offline when VPN is down even if host network reports connected")

	// 6. Underlying VPN reconnects -> online!
	s.OnNetworkEvent(watcher.Event{
		Kind:   watcher.EventUnderlyingVPNConnected,
		Name:   "corp-vpn",
		Reason: "vpn reconnected",
	})
	assert.True(t, s.netMgr.IsOnline(), "should be online after both host network and VPN are restored")
}
