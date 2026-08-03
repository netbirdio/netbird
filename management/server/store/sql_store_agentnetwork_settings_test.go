package store

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

// TestAgentNetworkSettings_SubdomainIsGloballyUnique is the guard for the whole
// allocation scheme: the label is now globally unique rather than per-cluster,
// and the allocator depends on the DATABASE saying no. Two different accounts on
// two different clusters must not be able to hold the same subdomain.
func TestAgentNetworkSettings_SubdomainIsGloballyUnique(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	first := &agentNetworkTypes.Settings{
		AccountID: "acc-unique-1",
		Cluster:   "eu.proxy.example",
		Subdomain: "brave-otter",
		Zone:      "gateway.example",
	}
	require.NoError(t, s.CreateAgentNetworkSettings(ctx, first), "first insert must succeed")

	// Deliberately a different account AND a different cluster: under the old
	// per-cluster scheme this was legal, and it is exactly what must now fail.
	second := &agentNetworkTypes.Settings{
		AccountID: "acc-unique-2",
		Cluster:   "us.proxy.example",
		Subdomain: "brave-otter",
		Zone:      "gateway.example",
	}
	err = s.CreateAgentNetworkSettings(ctx, second)
	require.Error(t, err, "duplicate subdomain must be rejected by the unique index")

	// The allocator recognises conflicts by matching the driver's message, so an
	// error that does not carry a unique-violation signature is useless to it
	// even though it is non-nil. These are the three signatures management's
	// isUniqueConstraintError matches (postgres / mysql / sqlite).
	msg := err.Error()
	assert.True(t,
		strings.Contains(msg, "(SQLSTATE 23505)") ||
			strings.Contains(msg, "Error 1062 (23000)") ||
			strings.Contains(msg, "UNIQUE constraint failed"),
		"error must be the raw driver error, recognisable as a unique violation; got %q", msg)
}

// TestAgentNetworkSettings_CreateThenReadBack keeps CreateAgentNetworkSettings
// honest as an insert path: the row it writes must be fully readable, including
// the new Zone column.
func TestAgentNetworkSettings_CreateThenReadBack(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	want := &agentNetworkTypes.Settings{
		AccountID: "acc-readback-1",
		Cluster:   "eu.proxy.example",
		Subdomain: "swift-heron",
		Zone:      "gateway.example",
	}
	require.NoError(t, s.CreateAgentNetworkSettings(ctx, want))

	got, err := s.GetAgentNetworkSettings(ctx, LockingStrengthNone, "acc-readback-1")
	require.NoError(t, err, "the inserted row must be readable")
	assert.Equal(t, "swift-heron", got.Subdomain)
	assert.Equal(t, "gateway.example", got.Zone, "the Zone column must round-trip")
	assert.Equal(t, "swift-heron.gateway.example", got.Endpoint(), "endpoint derives from zone")
}
