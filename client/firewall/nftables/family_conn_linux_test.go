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

// TestFamilySetConnectionSeparateFromRuleConnection guards the fix for
// https://github.com/netbirdio/netbird/discussions/7446. Named ipset
// (re)creation and element updates must go through their own dedicated
// connection (sConn) instead of sharing the rule connection (conn).
//
// Sharing a single netlink stream for both large set-element batches and
// rule installation can overload the batch and desync the kernel ack
// stream (google/nftables#170). The failure then surfaces as a spurious
// `conn.Receive: netlink receive: no such file or directory` when the rule
// that references the just-created source-IP set is flushed, so the inbound
// peer ACL never lands. Keeping the set connection separate (as the
// pre-#6322 implementation did) restores that separation while #6322's
// atomic install of a peer filter rule and its paired mangle rule is
// preserved: both still commit on conn in a single flush.
//
// The family instances are built through newFamily rather than struct
// literals so the test fails if the constructor ever collapses sConn and
// conn into a single connection.
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
				"set operations must use a connection distinct from the rule connection",
			)
		})
	}
}
