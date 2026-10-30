//go:build !ios && !android

package networkmonitor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

// Offline, Listen keeps the pre-loss baseline for the comparison but arms the
// checker with offlineCheckNextHops, and a default that comes back while the
// checker subscribes is still reported, even through the same router.
func TestListenWhileOfflineReportsTheReturnOfTheSameNetwork(t *testing.T) {
	home := NextHops{V4: systemops.Nexthop{IP: netip.MustParseAddr("192.168.1.1"), Intf: &net.Interface{Index: 13, Name: "Ethernet"}}}

	var mu sync.Mutex
	reads := 0
	readSnapshotFn = func() (NextHops, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		if reads == 1 {
			return NextHops{}, vars.ErrRouteNotFound // offline when the round starts
		}
		return home, nil // the same network is back
	}
	var gotV4 systemops.Nexthop
	checkChangeFn = func(ctx context.Context, v4, _ systemops.Nexthop) error {
		mu.Lock()
		gotV4 = v4
		mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	t.Cleanup(func() {
		readSnapshotFn = readSnapshot
		checkChangeFn = checkChange
	})

	nw := New()
	defer nw.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*debounceTime)
	defer cancel()

	change, err := nw.Listen(ctx, home)
	require.NoError(t, err, "the network coming back must be reported, not time out")
	assert.Equal(t, ChangeNone, change.Kind, "same network as before the loss")
	assert.Equal(t, home, change.Before, "compared with the pre-loss snapshot")

	wantV4, _ := offlineCheckNextHops(home.V4, home.V6)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, wantV4, gotV4, "offline the checker is armed with the offline next hops")
}

// A failed lookup when the round starts says nothing about the network: the
// round must not take it for offline and report the next read of the same
// network as the network coming back.
func TestListenTreatsALookupErrorAsUnknownNotOffline(t *testing.T) {
	home := NextHops{V4: systemops.Nexthop{IP: netip.MustParseAddr("192.168.1.1"), Intf: &net.Interface{Index: 13, Name: "Ethernet"}}}

	var mu sync.Mutex
	reads := 0
	readSnapshotFn = func() (NextHops, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		if reads == 1 {
			return NextHops{}, errors.New("netlink: interrupted")
		}
		return home, nil
	}
	checkChangeFn = func(ctx context.Context, _, _ systemops.Nexthop) error {
		<-ctx.Done()
		return ctx.Err()
	}
	t.Cleanup(func() {
		readSnapshotFn = readSnapshot
		checkChangeFn = checkChange
	})

	nw := New()
	defer nw.Stop()
	// Nothing changed and no event fires: the round must still be listening
	// when its deadline passes, past one debounce.
	ctx, cancel := context.WithTimeout(context.Background(), debounceTime+time.Second)
	defer cancel()
	_, err := nw.Listen(ctx, home)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "no change may be reported for an unchanged network after a failed lookup")
}
