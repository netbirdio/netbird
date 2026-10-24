package mcpapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUsageCountsTheLastDay(t *testing.T) {
	u := NewUsage()
	start := time.Date(2026, 10, 24, 9, 30, 0, 0, time.UTC)

	u.record("user-1", start)
	u.record("user-1", start.Add(time.Minute))
	u.record("user-2", start.Add(5*time.Hour))
	calls, users := u.LastDay(start.Add(5 * time.Hour))
	assert.Equal(t, 3, calls, "calls in the last day")
	assert.Equal(t, 2, users, "a user who called twice counts once")

	calls, users = u.LastDay(start.Add(24 * time.Hour))
	assert.Equal(t, 1, calls, "the first hour has left the window")
	assert.Equal(t, 1, users)

	// The bucket of the first hour is reused a day later and starts empty.
	u.record("user-3", start.Add(24*time.Hour))
	calls, users = u.LastDay(start.Add(24 * time.Hour))
	assert.Equal(t, 2, calls)
	assert.Equal(t, 2, users)

	calls, users = u.LastDay(start.Add(48 * time.Hour))
	assert.Zero(t, calls, "nothing older than a day is reported")
	assert.Zero(t, users)
}

func TestUsageNilCountsNothing(t *testing.T) {
	var u *Usage
	u.record("user-1", time.Now())
	calls, users := u.LastDay(time.Now())
	assert.Zero(t, calls)
	assert.Zero(t, users)
}
