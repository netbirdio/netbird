//go:build !android && privileged

package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connTestIface is a minimal iFaceMapper for constructor-level tests. It is
// only exercised for its Name, which the family constructor uses when
// building the IP forwarding state.
type connTestIface struct{}

func (connTestIface) Name() string { return "wg-test" }

func (connTestIface) Address() wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.MustParseAddr("100.96.0.1"),
		Network: netip.MustParsePrefix("100.96.0.0/16"),
	}
}

// TestFamilySetConnectionSeparateFromRuleConnection records that later
// element updates still use a dedicated connection. Named-set creation
// itself is queued on conn with the rule that looks it up; splitting only
// the add/delete path does not fix ENOENT on that lookup (see
// https://github.com/netbirdio/netbird/discussions/7446).
func TestFamilySetConnectionSeparateFromRuleConnection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family nftables.TableFamily
		table  string
	}{
		{name: "IPv4", family: nftables.TableFamilyIPv4, table: "netbird"},
		{name: "IPv6", family: nftables.TableFamilyIPv6, table: "netbird"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFamily(&nftables.Table{Name: tc.table, Family: tc.family}, connTestIface{}, iface.DefaultMTU)

			require.NotNil(t, r.conn, "rule connection must not be nil")
			require.NotNil(t, r.sConn, "set connection must not be nil")
			assert.NotSame(
				t,
				r.conn,
				r.sConn,
				"later set-element updates must use a connection distinct from the rule connection",
			)
			require.NotNil(t, r.pendingSetElements, "pending set-element map must be initialized")
		})
	}
}
