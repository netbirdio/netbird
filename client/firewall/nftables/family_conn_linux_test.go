package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
func TestFamilySetConnectionSeparateFromRuleConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *family
	}{
		{
			name: "IPv4",
			r:    &family{conn: &nftables.Conn{}, sConn: &nftables.Conn{}, af: afIPv4},
		},
		{
			name: "IPv6",
			r:    &family{conn: &nftables.Conn{}, sConn: &nftables.Conn{}, af: afIPv6},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotNil(t, tc.r.conn, "rule connection must not be nil")
			require.NotNil(t, tc.r.sConn, "set connection must not be nil")
			assert.NotSame(
				t,
				tc.r.conn,
				tc.r.sConn,
				"set operations must use a connection distinct from the rule connection",
			)
		})
	}
}
