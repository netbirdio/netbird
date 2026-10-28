//go:build darwin && !ios && privileged

package systemops

import (
	"net"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// A refresh runs with the NetBird routes in place. A socket NetBird dials
// while it runs must stay bound to the physical interface: unbound, it
// follows the NetBird split default into the tunnel. A utun stands in for
// the NetBird interface and a TEST-NET-1 route for the split default, so the
// host keeps its own connectivity; a socket that escaped the binding shows
// the tunnel's source address.
func TestRefreshUnderlayKeepsSocketsBound(t *testing.T) {
	nbnet.Init()
	require.True(t, nbnet.AdvancedRouting(), "advanced routing must be on")

	dev, err := tun.CreateTUN("utun", 1280)
	require.NoError(t, err, "create the stand-in tunnel")
	t.Cleanup(func() { _ = dev.Close() })
	tunName, err := dev.Name()
	require.NoError(t, err)
	const tunAddr = "100.64.250.1"
	out, err := exec.Command("ifconfig", tunName, "inet", tunAddr, tunAddr, "up").CombinedOutput()
	require.NoError(t, err, "address the stand-in tunnel: %s", out)
	overlaySource := net.ParseIP(tunAddr)

	prevVPN := nbnet.GetVPNInterfaceName()
	nbnet.SetVPNInterfaceName(tunName)
	t.Cleanup(func() { nbnet.SetVPNInterfaceName(prevVPN) })

	r := New(nil, nil)
	require.NoError(t, r.setupAdvancedRouting())
	t.Cleanup(func() { _ = r.cleanupAdvancedRouting() })

	const overlayNet = "192.0.2.0/24"
	out, err = exec.Command("route", "-n", "add", "-net", overlayNet, "-interface", tunName).CombinedOutput()
	require.NoError(t, err, "add the stand-in split route: %s", out)
	t.Cleanup(func() { _ = exec.Command("route", "-n", "delete", "-net", overlayNet, "-interface", tunName).Run() })

	const target = "192.0.2.1:53"
	sourceOf := func(t *testing.T, d interface {
		Dial(string, string) (net.Conn, error)
	}) net.IP {
		t.Helper()
		c, err := d.Dial("udp4", target)
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		return c.LocalAddr().(*net.UDPAddr).IP
	}

	// Preconditions, or the run below proves nothing: an unbound socket takes
	// the stand-in split route, a bound one the physical interface.
	unbound := sourceOf(t, &net.Dialer{})
	require.True(t, unbound.Equal(overlaySource), "an unbound socket must follow the stand-in split route, left from %s", unbound)
	bound := sourceOf(t, nbnet.NewDialer())
	require.False(t, bound.Equal(overlaySource), "a bound socket must leave through the physical interface, left from %s", bound)

	const rounds = 300
	var refreshErrs atomic.Int64
	refreshed := make(chan struct{})
	go func() {
		defer close(refreshed)
		for range rounds {
			if err := r.RefreshUnderlay(true); err != nil {
				refreshErrs.Add(1)
				t.Logf("refresh: %v", err)
			}
		}
	}()

	var sockets, intoOverlay int
	deadline := time.After(2 * time.Minute)
	for done := false; !done; {
		select {
		case <-refreshed:
			done = true
		case <-deadline:
			t.Fatalf("%d refreshes did not finish in time", rounds)
		default:
			sockets++
			if sourceOf(t, nbnet.NewDialer()).Equal(overlaySource) {
				intoOverlay++
			}
		}
	}

	t.Logf("%d refreshes, %d sockets dialed meanwhile", rounds, sockets)
	assert.Zero(t, refreshErrs.Load(), "refreshes on an unchanged network must succeed")
	assert.Zero(t, intoOverlay, "sockets dialed during a refresh must stay on the physical interface")
}
