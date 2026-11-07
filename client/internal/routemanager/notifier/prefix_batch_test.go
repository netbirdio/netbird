package notifier

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prefixesOf(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}

func TestPrefixBatch_NoBatchAnnouncesImmediately(t *testing.T) {
	var b prefixBatch

	assert.False(t, b.hold(prefixesOf("10.0.0.0/24")), "outside a batch nothing should be held")

	_, ok := b.end()
	assert.False(t, ok, "end without begin must not release anything")
}

// Every route the manager adds during a network map update announces the whole
// prefix set, so within a batch only the last announcement is the end result.
func TestPrefixBatch_ReleasesNewestOnEnd(t *testing.T) {
	var b prefixBatch
	b.begin()

	require.True(t, b.hold(prefixesOf("10.0.0.0/24")))
	require.True(t, b.hold(prefixesOf("10.0.0.0/24", "10.1.0.0/24")))

	got, ok := b.end()
	require.True(t, ok, "the outermost end must release the held prefixes")
	assert.Equal(t, prefixesOf("10.0.0.0/24", "10.1.0.0/24"), got, "only the newest set should be released")

	_, ok = b.end()
	assert.False(t, ok, "a closed batch must not release again")
}

func TestPrefixBatch_EmptyBatchReleasesNothing(t *testing.T) {
	var b prefixBatch
	b.begin()

	_, ok := b.end()
	assert.False(t, ok, "a batch without announcements has nothing to release")
}

// Routing cleanup announces an empty set. It must reach the listener, so an
// empty announcement must not be mistaken for no announcement.
func TestPrefixBatch_HoldsEmptySet(t *testing.T) {
	var b prefixBatch
	b.begin()

	require.True(t, b.hold(nil))

	got, ok := b.end()
	require.True(t, ok, "an announced empty set must be released")
	assert.Empty(t, got, "the released set should be empty")
}

func TestPrefixBatch_NestedBatchesReleaseOnOutermostEnd(t *testing.T) {
	var b prefixBatch
	b.begin()
	b.begin()

	require.True(t, b.hold(prefixesOf("10.0.0.0/24")))

	_, ok := b.end()
	assert.False(t, ok, "closing an inner batch must not release")

	got, ok := b.end()
	require.True(t, ok, "closing the outermost batch must release")
	assert.Equal(t, prefixesOf("10.0.0.0/24"), got, "the held set should be released once")
}
