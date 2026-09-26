//go:build linux && !android

package watcher

import (
	"net"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestNetworkManagerWatcher_HandleActiveConnectionStateChanged(t *testing.T) {
	tests := []struct {
		name             string
		path             dbus.ObjectPath
		state            uint32
		reason           uint32
		conns            map[dbus.ObjectPath]activeConnInfo
		expectedEvents   int
		expectedKind     EventKind
		expectedUserInit bool
	}{
		{
			name:   "NetBird interface user disconnected",
			path:   "/org/freedesktop/NetworkManager/ActiveConnection/1",
			state:  nmActiveStateDeactivated,
			reason: nmActiveReasonUserDisconnected,
			conns: map[dbus.ObjectPath]activeConnInfo{
				"/org/freedesktop/NetworkManager/ActiveConnection/1": {
					id:     "wt0",
					cType:  "wireguard",
					device: "wt0",
				},
			},
			expectedEvents:   1,
			expectedKind:     EventNetBirdInterfaceDisconnected,
			expectedUserInit: true,
		},
		{
			name:   "Underlying corporate VPN disconnected",
			path:   "/org/freedesktop/NetworkManager/ActiveConnection/2",
			state:  nmActiveStateDeactivating,
			reason: nmActiveReasonUserDisconnected,
			conns: map[dbus.ObjectPath]activeConnInfo{
				"/org/freedesktop/NetworkManager/ActiveConnection/2": {
					id:    "corporate-vpn",
					cType: "vpn",
					vpn:   true,
				},
			},
			expectedEvents:   1,
			expectedKind:     EventUnderlyingVPNDisconnected,
			expectedUserInit: true,
		},
		{
			name:   "Underlying VPN connected",
			path:   "/org/freedesktop/NetworkManager/ActiveConnection/3",
			state:  nmActiveStateActivated,
			reason: 0,
			conns: map[dbus.ObjectPath]activeConnInfo{
				"/org/freedesktop/NetworkManager/ActiveConnection/3": {
					id:    "corporate-vpn",
					cType: "vpn",
					vpn:   true,
				},
			},
			expectedEvents:   1,
			expectedKind:     EventUnderlyingVPNConnected,
			expectedUserInit: false,
		},
		{
			name:   "Unrelated interface state change ignored",
			path:   "/org/freedesktop/NetworkManager/ActiveConnection/4",
			state:  nmActiveStateActivated,
			reason: 0,
			conns: map[dbus.ObjectPath]activeConnInfo{
				"/org/freedesktop/NetworkManager/ActiveConnection/4": {
					id:    "eth0",
					cType: "802-3-ethernet",
					vpn:   false,
				},
			},
			expectedEvents: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newNetworkManagerWatcher("wt0")
			w.activeConns = tt.conns

			var events []Event
			var mu sync.Mutex

			handler := HandlerFunc(func(ev Event) {
				mu.Lock()
				events = append(events, ev)
				mu.Unlock()
			})

			sig := &dbus.Signal{
				Path: tt.path,
				Name: nmActiveConnIface + "." + nmSignalStateChanged,
				Body: []any{tt.state, tt.reason},
			}

			w.handleActiveConnectionStateChanged(nil, sig, handler)

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, events, tt.expectedEvents)
			if tt.expectedEvents > 0 {
				assert.Equal(t, tt.expectedKind, events[0].Kind)
				assert.Equal(t, tt.expectedUserInit, events[0].UserInitiated)
			}
		})
	}
}

func TestNetworkManagerWatcher_HandleDeviceStateChanged(t *testing.T) {
	w := newNetworkManagerWatcher("wt0")
	w.deviceIfaces["/org/freedesktop/NetworkManager/Devices/9"] = "wt0"

	var events []Event
	var mu sync.Mutex

	handler := HandlerFunc(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	sig := &dbus.Signal{
		Path: "/org/freedesktop/NetworkManager/Devices/9",
		Name: nmDeviceIface + "." + nmSignalStateChanged,
		Body: []any{nmDeviceStateDisconnected, nmDeviceStateActivated, nmDeviceReasonUserRequested},
	}

	w.handleDeviceStateChanged(nil, sig, handler)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1)
	assert.Equal(t, EventNetBirdInterfaceDisconnected, events[0].Kind)
	assert.Equal(t, "wt0", events[0].Name)
	assert.True(t, events[0].UserInitiated)
}

func TestNetworkManagerWatcher_HandleNMStateChanged(t *testing.T) {
	w := newNetworkManagerWatcher("wt0")

	var events []Event
	var mu sync.Mutex

	handler := HandlerFunc(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	// Disconnected
	sigDisconnected := &dbus.Signal{
		Path: nmPath,
		Name: nmInterface + "." + nmSignalStateChanged,
		Body: []any{nmStateDisconnected},
	}
	w.handleNMStateChanged(sigDisconnected, handler)

	// Connected
	sigConnected := &dbus.Signal{
		Path: nmPath,
		Name: nmInterface + "." + nmSignalStateChanged,
		Body: []any{nmStateConnected},
	}
	w.handleNMStateChanged(sigConnected, handler)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventNetworkDisconnected, events[0].Kind)
	assert.Equal(t, EventNetworkConnected, events[1].Kind)
}

func TestNetworkManagerWatcher_HandleNMPropertiesChanged(t *testing.T) {
	w := newNetworkManagerWatcher("wt0")

	var events []Event
	var mu sync.Mutex

	handler := HandlerFunc(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	// Connectivity lost (NM_CONNECTIVITY_NONE = 1)
	sigNone := &dbus.Signal{
		Path: nmPath,
		Name: dbusPropertiesIface + ".PropertiesChanged",
		Body: []any{
			nmInterface,
			map[string]dbus.Variant{
				"Connectivity": dbus.MakeVariant(nmConnectivityNone),
			},
			[]string{},
		},
	}
	w.handlePropertiesChanged(nil, sigNone, handler)

	// Connectivity full (NM_CONNECTIVITY_FULL = 4)
	sigFull := &dbus.Signal{
		Path: nmPath,
		Name: dbusPropertiesIface + ".PropertiesChanged",
		Body: []any{
			nmInterface,
			map[string]dbus.Variant{
				"Connectivity": dbus.MakeVariant(uint32(4)),
			},
			[]string{},
		},
	}
	w.handlePropertiesChanged(nil, sigFull, handler)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventNetworkDisconnected, events[0].Kind)
	assert.Equal(t, EventNetworkConnected, events[1].Kind)
}

func TestNetlinkWatcher_HandleLinkUpdate(t *testing.T) {
	w := newNetlinkWatcher("wt0")

	var events []Event
	var mu sync.Mutex

	handler := HandlerFunc(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	// wt0 with FlagUp cleared should emit EventNetBirdInterfaceDisconnected
	updateDown := netlink.LinkUpdate{
		Link: &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "wt0",
				Flags: 0,
			},
		},
	}
	w.handleLinkUpdate(updateDown, handler)

	// wt0 with FlagUp set should not emit
	updateUp := netlink.LinkUpdate{
		Link: &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "wt0",
				Flags: net.FlagUp,
			},
		},
	}
	w.handleLinkUpdate(updateUp, handler)

	// Unrelated interface should not emit
	updateOther := netlink.LinkUpdate{
		Link: &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "eth0",
				Flags: 0,
			},
		},
	}
	w.handleLinkUpdate(updateOther, handler)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1)
	assert.Equal(t, EventNetBirdInterfaceDisconnected, events[0].Kind)
	assert.Equal(t, "wt0", events[0].Name)
}

func TestSystemdNetworkdWatcher_HandleSignal(t *testing.T) {
	w := newSystemdNetworkdWatcher("wt0")

	var events []Event
	var mu sync.Mutex

	handler := HandlerFunc(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	// OperationalState = off
	sigOff := &dbus.Signal{
		Path: systemdNetworkdPath,
		Name: dbusPropertiesIface + ".PropertiesChanged",
		Body: []any{
			systemdNetworkdManagerIface,
			map[string]dbus.Variant{
				"OperationalState": dbus.MakeVariant("off"),
			},
			[]string{},
		},
	}
	w.handleSignal(sigOff, handler)

	// OperationalState = routable
	sigRoutable := &dbus.Signal{
		Path: systemdNetworkdPath,
		Name: dbusPropertiesIface + ".PropertiesChanged",
		Body: []any{
			systemdNetworkdManagerIface,
			map[string]dbus.Variant{
				"OperationalState": dbus.MakeVariant("routable"),
			},
			[]string{},
		},
	}
	w.handleSignal(sigRoutable, handler)

	// Link AdministrativeState = down
	sigLinkDown := &dbus.Signal{
		Path: "/org/freedesktop/network1/link/_12",
		Name: dbusPropertiesIface + ".PropertiesChanged",
		Body: []any{
			systemdNetworkdLinkIface,
			map[string]dbus.Variant{
				"AdministrativeState": dbus.MakeVariant("down"),
			},
			[]string{},
		},
	}
	w.handleSignal(sigLinkDown, handler)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 3)
	assert.Equal(t, EventNetworkDisconnected, events[0].Kind)
	assert.Equal(t, EventNetworkConnected, events[1].Kind)
	assert.Equal(t, EventNetBirdInterfaceDisconnected, events[2].Kind)
}
