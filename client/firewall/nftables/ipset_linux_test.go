package nftables

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertPrefixesToSetWildcard verifies that a /0 prefix produces a
// usable interval. The last address of a /0 is the broadcast, whose Next()
// overflows to an invalid Addr with an empty key; the IntervalEnd must wrap
// to the zero address instead so nftables sees a full-range interval.
func TestConvertPrefixesToSetWildcard(t *testing.T) {
	tests := []struct {
		name   string
		af     addrFamily
		prefix string
	}{
		{"IPv4 /0", afIPv4, "0.0.0.0/0"},
		{"IPv6 /0", afIPv6, "::/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &family{af: tt.af}
			elements := r.convertPrefixesToSet([]netip.Prefix{netip.MustParsePrefix(tt.prefix)})

			require.Len(t, elements, 2, "expected start and interval-end element")
			assert.False(t, elements[0].IntervalEnd, "first element is the interval start")
			assert.True(t, elements[1].IntervalEnd, "second element is the interval end")
			assert.Len(t, elements[1].Key, int(tt.af.addrLen), "interval-end key must be a zero address, not empty")
		})
	}
}

func pendingUpdate(name string) pendingSetUpdate {
	return pendingSetUpdate{
		set:      &nftables.Set{Name: name},
		elements: []nftables.SetElement{{Key: []byte{1}}, {Key: []byte{2}}},
	}
}

func TestDiscardPendingSetsLeavesUnrelated(t *testing.T) {
	r := &family{pendingSetElements: map[string]pendingSetUpdate{
		"keep": pendingUpdate("keep"),
		"drop": pendingUpdate("drop"),
	}}

	r.discardPendingSets([]string{"drop"})

	_, keep := r.pendingSetElements["keep"]
	_, drop := r.pendingSetElements["drop"]
	assert.True(t, keep, "unrelated pending work must survive")
	assert.False(t, drop, "queued set of the failing call must be dropped")
}

func TestDiscardPendingSetElementsClearsAll(t *testing.T) {
	r := &family{pendingSetElements: map[string]pendingSetUpdate{
		"a": pendingUpdate("a"),
		"b": pendingUpdate("b"),
	}}

	r.discardPendingSetElements()

	assert.Empty(t, r.pendingSetElements)
}

func TestPendingAddedSince(t *testing.T) {
	r := &family{pendingSetElements: map[string]pendingSetUpdate{
		"old": pendingUpdate("old"),
		"new": pendingUpdate("new"),
	}}

	added := r.pendingAddedSince(map[string]struct{}{"old": {}})
	assert.ElementsMatch(t, []string{"new"}, added)
}

func TestCommitPendingSetsRetriesThenSucceeds(t *testing.T) {
	attempts := 0
	r := &family{
		sConn:              &nftables.Conn{},
		pendingSetElements: map[string]pendingSetUpdate{"s": pendingUpdate("s")},
		testPendingFlush: func() error {
			attempts++
			if attempts < pendingSetCommitAttempts {
				return fmt.Errorf("netlink busy")
			}
			return nil
		},
	}

	require.NoError(t, r.commitPendingSets([]string{"s"}))
	assert.Equal(t, pendingSetCommitAttempts, attempts)
	assert.Empty(t, r.pendingSetElements)
}

func TestCommitPendingSetsRetriesThenKeepsRemaining(t *testing.T) {
	r := &family{
		sConn:              &nftables.Conn{},
		pendingSetElements: map[string]pendingSetUpdate{"s": pendingUpdate("s")},
		testPendingFlush: func() error {
			return fmt.Errorf("netlink busy")
		},
	}

	err := r.commitPendingSets([]string{"s"})
	require.Error(t, err)
	_, ok := r.pendingSetElements["s"]
	assert.True(t, ok, "failed overflow must remain queued for rollback to discard")
}

func TestCommitPendingSetsSkipsUnrelated(t *testing.T) {
	flushed := 0
	r := &family{
		sConn: &nftables.Conn{},
		pendingSetElements: map[string]pendingSetUpdate{
			"a": pendingUpdate("a"),
			"b": pendingUpdate("b"),
		},
		testPendingFlush: func() error {
			flushed++
			return nil
		},
	}

	require.NoError(t, r.commitPendingSets([]string{"a"}))
	assert.Equal(t, 1, flushed)
	_, a := r.pendingSetElements["a"]
	_, b := r.pendingSetElements["b"]
	assert.False(t, a)
	assert.True(t, b, "sets not named by this commit must stay queued")
}

func TestCommitOverflowOrRollbackDiscardsQueuedOnly(t *testing.T) {
	rolled := false
	r := &family{
		sConn: &nftables.Conn{},
		pendingSetElements: map[string]pendingSetUpdate{
			"keep": pendingUpdate("keep"),
			"drop": pendingUpdate("drop"),
		},
		testPendingFlush: func() error {
			return fmt.Errorf("netlink busy")
		},
	}

	err := r.commitOverflowOrRollback([]string{"drop"}, func() { rolled = true })
	require.Error(t, err)
	assert.True(t, rolled, "live rule must be torn down after overflow retries fail")

	_, keep := r.pendingSetElements["keep"]
	_, drop := r.pendingSetElements["drop"]
	assert.True(t, keep, "unrelated pending prefixes must not be discarded")
	assert.False(t, drop)
}

func TestCommitOverflowOrRollbackEmptyQueued(t *testing.T) {
	rolled := false
	r := &family{
		pendingSetElements: map[string]pendingSetUpdate{
			"keep": pendingUpdate("keep"),
		},
		testPendingFlush: func() error {
			return fmt.Errorf("netlink busy")
		},
	}

	require.NoError(t, r.commitOverflowOrRollback(nil, func() { rolled = true }))
	assert.False(t, rolled)
	_, keep := r.pendingSetElements["keep"]
	assert.True(t, keep)
}
