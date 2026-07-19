package peer

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

type endpointTestWGIface struct {
	mu          sync.Mutex
	updateCalls int
	removeCalls int
}

func (m *endpointTestWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	return nil
}

func (m *endpointTestWGIface) RemovePeer(string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeCalls++
	return nil
}

func (m *endpointTestWGIface) GetStats() (map[string]configurer.WGStats, error) { return nil, nil }

func (m *endpointTestWGIface) GetProxy() wgproxy.Proxy { return nil }

func (m *endpointTestWGIface) Address() wgaddr.Address { return wgaddr.Address{} }

func (m *endpointTestWGIface) RemoveEndpointAddress(string) error { return nil }

func (m *endpointTestWGIface) counts() (updates, removes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updateCalls, m.removeCalls
}

func newTestEndpointUpdater(iface *endpointTestWGIface, initiator bool) *EndpointUpdater {
	cfg := WgConfig{
		RemoteKey:   "remoteKey",
		WgInterface: iface,
		AllowedIps:  []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
	}
	return NewEndpointUpdater(log.WithField("peer", "test"), cfg, initiator)
}

// TestEndpointUpdater_CancelPendingUpdates ensures a scheduled responder-side delayed
// update is stopped without removing the WireGuard peer, so an idle transition cannot
// be overwritten later by a stale endpoint update.
func TestEndpointUpdater_CancelPendingUpdates(t *testing.T) {
	iface := &endpointTestWGIface{}
	e := newTestEndpointUpdater(iface, false)

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}
	require.NoError(t, e.ConfigureWGEndpoint(addr, nil))

	updates, _ := iface.counts()
	require.Equal(t, 1, updates, "responder must apply the immediate nil-endpoint update")

	// CancelPendingUpdates waits for the delayed-update goroutine to exit, so the
	// call counts below are final: the 5s fallback update can never fire anymore.
	e.CancelPendingUpdates()

	updates, removes := iface.counts()
	assert.Equal(t, 1, updates, "delayed endpoint update must not fire after cancellation")
	assert.Equal(t, 0, removes, "cancellation must not remove the WireGuard peer")
}

// TestEndpointUpdater_CancelPendingUpdatesNoPending ensures cancellation is a safe no-op
// when no delayed update is scheduled (initiator path).
func TestEndpointUpdater_CancelPendingUpdatesNoPending(t *testing.T) {
	iface := &endpointTestWGIface{}
	e := newTestEndpointUpdater(iface, true)

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}
	require.NoError(t, e.ConfigureWGEndpoint(addr, nil))

	e.CancelPendingUpdates()

	updates, removes := iface.counts()
	assert.Equal(t, 1, updates, "initiator applies exactly one direct update")
	assert.Equal(t, 0, removes, "cancellation must not remove the WireGuard peer")
}
