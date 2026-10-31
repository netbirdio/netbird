//go:build privileged && linux && !android

package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

// TestExchangeWithFallback_OfflinePeerFailsFast guards the behaviour DNS upstreams and the DNS route
// interceptor rely on when the peer that serves a query is not connected yet: the exchange over a real
// kernel interface has to fail at once, not run into its timeout. A change that makes the device hold
// such packets, for instance by giving the peer that reserves the overlay range an endpoint, would turn
// every query to an offline peer into a full timeout.
func TestExchangeWithFallback_OfflinePeerFailsFast(t *testing.T) {
	if !device.WireGuardModuleIsLoaded() {
		t.Skip("kernel WireGuard is not available here")
	}

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	w, err := iface.NewWGIFace(iface.WGIFaceOpts{
		IFaceName:    "utun2060",
		Address:      wgaddr.MustParseWGAddress("100.64.0.1/16"),
		WGPort:       33260,
		WGPrivKey:    priv.String(),
		MTU:          iface.DefaultMTU,
		TransportNet: stdnet.NewNet(context.Background(), []string{"wt", "utun", "tun0"}, nil),
	})
	require.NoError(t, err)
	require.NoError(t, w.Create())
	t.Cleanup(func() { _ = w.Close() })
	_, err = w.Up()
	require.NoError(t, err)

	upstreamIP := netip.MustParseAddr("100.64.0.77")
	const timeout = 8 * time.Second

	client, err := GetClientPrivate(w, upstreamIP, timeout)
	require.NoError(t, err)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	_, _, err = ExchangeWithFallback(ctx, client, msg, "100.64.0.77:5053")
	elapsed := time.Since(start)

	require.Error(t, err, "nobody answers for a peer that is not connected")
	assert.False(t, errors.Is(err, context.DeadlineExceeded), "the failure must not be the timeout: %v", err)
	assert.Less(t, elapsed, 2*time.Second, "the exchange must fail at once, took %v: %v", elapsed, err)
	t.Logf("exchange with an offline peer failed after %v: %v", elapsed.Round(time.Millisecond), err)
}
