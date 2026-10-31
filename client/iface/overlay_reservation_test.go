//go:build !android

package iface

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type fakePeer struct {
	allowedIPs []netip.Prefix
	endpoint   *net.UDPAddr
	keepAlive  time.Duration
}

// fakeConfigurer keeps the peers a device would have.
type fakeConfigurer struct {
	device.WGConfigurer

	peers     map[string]fakePeer
	updates   int
	removes   int
	updateErr error
	removeErr error
}

func newFakeConfigurer() *fakeConfigurer {
	return &fakeConfigurer{peers: map[string]fakePeer{}}
}

func (f *fakeConfigurer) UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, _ *wgtypes.Key) error {
	f.updates++
	if f.updateErr != nil {
		return f.updateErr
	}
	f.peers[peerKey] = fakePeer{allowedIPs: allowedIps, endpoint: endpoint, keepAlive: keepAlive}
	return nil
}

func (f *fakeConfigurer) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	p := f.peers[peerKey]
	p.allowedIPs = append(p.allowedIPs, allowedIP)
	f.peers[peerKey] = p
	return nil
}

func (f *fakeConfigurer) RemovePeer(peerKey string) error {
	f.removes++
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.peers, peerKey)
	return nil
}

type fakeTun struct {
	WGTunDevice

	addr          wgaddr.Address
	updateAddrErr error
}

func (f *fakeTun) WgAddress() wgaddr.Address { return f.addr }
func (f *fakeTun) DeviceName() string        { return "wt-test" }
func (f *fakeTun) UpdateAddr(a wgaddr.Address) error {
	if f.updateAddrErr != nil {
		return f.updateAddrErr
	}
	f.addr = a
	return nil
}

func v4Addr(cidr string) wgaddr.Address {
	return wgaddr.MustParseWGAddress(cidr)
}

func newReservationTestIface(addr wgaddr.Address) (*WGIface, *fakeConfigurer, *fakeTun) {
	cfg := newFakeConfigurer()
	tun := &fakeTun{addr: addr}
	return &WGIface{tun: tun, configurer: cfg}, cfg, tun
}

func TestOverlayPrefixes(t *testing.T) {
	t.Run("v4 only", func(t *testing.T) {
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, overlayPrefixes(v4Addr("100.64.3.9/16")))
	})

	t.Run("v4 and v6, host bits masked", func(t *testing.T) {
		addr := wgaddr.Address{
			IP:      netip.MustParseAddr("100.64.3.9"),
			Network: netip.MustParsePrefix("100.64.3.9/16"),
			IPv6:    netip.MustParseAddr("fd00:1::9"),
			IPv6Net: netip.MustParsePrefix("fd00:1::9/64"),
		}
		assert.Equal(t, []netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/16"),
			netip.MustParsePrefix("fd00:1::/64"),
		}, overlayPrefixes(addr))
	})
}

func TestWGIface_ReserveOverlay_AddsPlaceholderWithoutEndpoint(t *testing.T) {
	w, cfg, _ := newReservationTestIface(v4Addr("100.64.0.1/16"))

	require.NoError(t, w.reserveOverlay(false))

	require.Len(t, cfg.peers, 1)
	peer, ok := cfg.peers[w.overlayPeerKey]
	require.True(t, ok, "the placeholder must be the peer that was added")
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, peer.allowedIPs)
	assert.Nil(t, peer.endpoint, "the placeholder must never get an endpoint")
	assert.Zero(t, peer.keepAlive, "the placeholder must never send keepalives")
	assert.Zero(t, cfg.removes)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, w.overlayRange)
}

func TestWGIface_ReserveOverlay_KeyIsStableAndValid(t *testing.T) {
	w, _, _ := newReservationTestIface(v4Addr("100.64.0.1/16"))

	require.NoError(t, w.reserveOverlay(false))
	first := w.overlayPeerKey
	_, err := wgtypes.ParseKey(first)
	require.NoError(t, err)

	require.NoError(t, w.reserveOverlay(true))
	assert.Equal(t, first, w.overlayPeerKey, "replacing the reservation must keep the same peer")
}

func TestWGIface_ReserveOverlay_ReplaceDropsThePreviousRange(t *testing.T) {
	w, cfg, tun := newReservationTestIface(v4Addr("100.64.0.1/16"))
	require.NoError(t, w.reserveOverlay(false))

	tun.addr = v4Addr("100.65.0.1/16")
	require.NoError(t, w.reserveOverlay(true))

	require.Len(t, cfg.peers, 1)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.65.0.0/16")}, cfg.peers[w.overlayPeerKey].allowedIPs,
		"the old range must not stay reserved")
	assert.Equal(t, 1, cfg.removes)
}

func TestWGIface_ReserveOverlay_AfterReconfigureDoesNotRemove(t *testing.T) {
	w, cfg, _ := newReservationTestIface(v4Addr("100.64.0.1/16"))
	require.NoError(t, w.reserveOverlay(false))

	// configuring the device drops every peer, the placeholder included
	cfg.peers = map[string]fakePeer{}
	require.NoError(t, w.reserveOverlay(false))

	assert.Contains(t, cfg.peers, w.overlayPeerKey)
	assert.Zero(t, cfg.removes, "there is nothing left to remove after a reconfigure")
}

func TestWGIface_ReserveOverlay_UpdateFailureLeavesNothingReserved(t *testing.T) {
	w, cfg, _ := newReservationTestIface(v4Addr("100.64.0.1/16"))
	cfg.updateErr = errors.New("no device")

	err := w.reserveOverlay(false)
	require.Error(t, err)
	assert.ErrorContains(t, err, "reserve overlay range")
	assert.Empty(t, w.overlayRange)
	assert.Empty(t, cfg.peers)

	cfg.updateErr = nil
	require.NoError(t, w.reserveOverlay(false))
	assert.NotEmpty(t, w.overlayRange)
}

func TestWGIface_ReserveOverlay_ReleaseFailureKeepsTheOldReservation(t *testing.T) {
	w, cfg, tun := newReservationTestIface(v4Addr("100.64.0.1/16"))
	require.NoError(t, w.reserveOverlay(false))

	cfg.removeErr = errors.New("busy")
	tun.addr = v4Addr("100.65.0.1/16")
	err := w.reserveOverlay(true)
	require.Error(t, err)
	assert.ErrorContains(t, err, "release overlay range")

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, w.overlayRange, "the previous reservation is still in place")
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, cfg.peers[w.overlayPeerKey].allowedIPs)
}

func TestWGIface_ReserveOverlay_WithoutConfigurer(t *testing.T) {
	w := &WGIface{tun: &fakeTun{addr: v4Addr("100.64.0.1/16")}}

	assert.ErrorIs(t, w.reserveOverlay(false), ErrIfaceNotFound)
}

func TestWGIface_UpdateAddr_MovesTheReservation(t *testing.T) {
	w, cfg, _ := newReservationTestIface(v4Addr("100.64.0.1/16"))
	require.NoError(t, w.reserveOverlay(false))

	require.NoError(t, w.UpdateAddr(v4Addr("100.70.0.1/16")))

	require.Len(t, cfg.peers, 1)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.70.0.0/16")}, cfg.peers[w.overlayPeerKey].allowedIPs)
}

func TestWGIface_UpdateAddr_FailureKeepsTheReservation(t *testing.T) {
	w, cfg, tun := newReservationTestIface(v4Addr("100.64.0.1/16"))
	require.NoError(t, w.reserveOverlay(false))

	tun.updateAddrErr = errors.New("address in use")
	require.Error(t, w.UpdateAddr(v4Addr("100.70.0.1/16")))

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, cfg.peers[w.overlayPeerKey].allowedIPs,
		"a failed address change must not touch the reservation")
}

func TestWGIface_RefusesToGiveAPeerTheOverlayRange(t *testing.T) {
	w, cfg, _ := newReservationTestIface(wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/16"),
		IPv6:    netip.MustParseAddr("fd00:64::1"),
		IPv6Net: netip.MustParsePrefix("fd00:64::/64"),
	})
	require.NoError(t, w.reserveOverlay(false))
	reserved := map[string]fakePeer{}
	for k, v := range cfg.peers {
		reserved[k] = v
	}

	for _, p := range []string{"100.64.0.0/16", "100.64.7.9/16", "fd00:64::/64"} {
		err := w.UpdatePeer("peer", []netip.Prefix{netip.MustParsePrefix(p)}, 0, nil, nil)
		assert.ErrorIs(t, err, ErrOverlayRangeReserved, "UpdatePeer with %s", p)

		err = w.AddAllowedIP("peer", netip.MustParsePrefix(p))
		assert.ErrorIs(t, err, ErrOverlayRangeReserved, "AddAllowedIP with %s", p)
	}
	assert.NotContains(t, cfg.peers, "peer", "a refused call must not reach the device")
	assert.Equal(t, reserved, cfg.peers, "the placeholder must be untouched")
}

func TestWGIface_AllowsPrefixesThatDoNotConflictWithTheOverlayRange(t *testing.T) {
	w, cfg, _ := newReservationTestIface(v4Addr("100.64.0.1/16"))
	require.NoError(t, w.reserveOverlay(false))

	for _, p := range []string{
		"0.0.0.0/0",      // an exit node contains the range
		"100.64.0.41/32", // a peer's own address sits inside it
		"100.64.1.0/24",
		"10.0.0.0/24",
		"100.0.0.0/8",
	} {
		require.NoError(t, w.UpdatePeer("peer", []netip.Prefix{netip.MustParsePrefix(p)}, 0, nil, nil), p)
		require.NoError(t, w.AddAllowedIP("peer", netip.MustParsePrefix(p)), p)
	}

	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, cfg.peers[w.overlayPeerKey].allowedIPs)
}

func TestWGIface_OverlayGuardFollowsTheReservedRange(t *testing.T) {
	w, _, tun := newReservationTestIface(v4Addr("100.64.0.1/16"))

	// nothing is reserved yet, so nothing is refused
	require.NoError(t, w.UpdatePeer("peer", []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, 0, nil, nil))

	require.NoError(t, w.reserveOverlay(false))
	tun.addr = v4Addr("100.70.0.1/16")
	require.NoError(t, w.reserveOverlay(true))

	assert.NoError(t, w.AddAllowedIP("peer", netip.MustParsePrefix("100.64.0.0/16")), "the old range is free again")
	assert.ErrorIs(t, w.AddAllowedIP("peer", netip.MustParsePrefix("100.70.0.0/16")), ErrOverlayRangeReserved)
}
