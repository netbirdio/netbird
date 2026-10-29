package peerauth

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClock_FollowsManagementTime(t *testing.T) {
	var nilClock *Clock
	assert.WithinDuration(t, time.Now(), nilClock.Now(), time.Second, "a nil clock must be the local clock")

	var c Clock
	assert.WithinDuration(t, time.Now(), c.Now(), time.Second, "without Management time the clock must be the local one")

	// The local clock is an hour behind Management.
	c.SetManagementTime(time.Now().Add(time.Hour))
	assert.WithinDuration(t, time.Now().Add(time.Hour), c.Now(), time.Second, "proofs must be signed on Management time")

	// A later Management time, e.g. from a sync, replaces the reference.
	c.SetManagementTime(time.Now().Add(-time.Hour))
	assert.WithinDuration(t, time.Now().Add(-time.Hour), c.Now(), time.Second, "the last Management time seen must win")
}

func TestClock_AdvancesFromManagementTime(t *testing.T) {
	var c Clock
	management := time.Now().Add(time.Hour)
	c.SetManagementTime(management)

	// The clock must keep running after the Management time was recorded, never freeze on it.
	require.Eventually(t, func() bool { return c.Now().After(management.Add(time.Millisecond)) },
		time.Second, time.Millisecond, "the clock must advance from the Management time")
}

func TestClock_MeasuresElapsedOnMonotonicClock(t *testing.T) {
	var c Clock
	c.SetManagementTime(time.Now())

	// A wall clock step cannot be simulated in a test: assert the reference keeps the monotonic
	// reading time.Since uses, which a wall clock step does not move. time.Time.String prints it
	// as "m=±<seconds>".
	ref := c.ref.Load()
	require.NotNil(t, ref)
	assert.True(t, strings.Contains(ref.local.String(), " m="), "the elapsed time must be measured on the monotonic clock")
}
