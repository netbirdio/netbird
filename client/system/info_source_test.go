package system

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestInfoSource_CurrentBeforeRefresh(t *testing.T) {
	var src InfoSource

	info := src.Current(context.Background())

	assert.Empty(t, info.Files)
}

func TestInfoSource_CurrentReusesRefreshedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	checks := []*proto.Checks{{Files: []string{path}}}

	var src InfoSource
	refreshed, ok := src.Refresh(context.Background(), 15*time.Second, checks)
	require.True(t, ok)
	require.Equal(t, []File{{Path: path, Exist: true}}, refreshed.Files)

	info := src.Current(context.Background())

	assert.Equal(t, refreshed.Files, info.Files)
}

// TestInfoSource_RefreshSkipsWhileEarlierGatheringRuns stands in for a gathering that
// timed out and is still blocked in a system call: no second one starts on top of it,
// and gathering works again once it exits.
func TestInfoSource_RefreshSkipsWhileEarlierGatheringRuns(t *testing.T) {
	var src InfoSource
	src.gathering.Store(true)

	_, ok := src.Refresh(context.Background(), 15*time.Second, nil)
	assert.False(t, ok, "no gathering starts while an earlier one is still running")

	src.gathering.Store(false)
	_, ok = src.Refresh(context.Background(), 15*time.Second, nil)
	require.True(t, ok, "gathering runs once the earlier one exited")

	_, ok = src.Refresh(context.Background(), 15*time.Second, nil)
	assert.True(t, ok, "a gathering that finished in time does not block the next one")
}

// TestInfoSource_RefreshReleasesAfterTimedOutGatheringExits checks that a gathering that
// timed out releases the source once its goroutine finishes, not before.
func TestInfoSource_RefreshReleasesAfterTimedOutGatheringExits(t *testing.T) {
	var src InfoSource

	_, ok := src.Refresh(context.Background(), time.Nanosecond, nil)
	require.False(t, ok, "gathering cannot finish within a nanosecond")

	require.Eventually(t, func() bool { return !src.gathering.Load() }, 10*time.Second, 10*time.Millisecond,
		"the source is released when the abandoned gathering exits")
	_, ok = src.Refresh(context.Background(), 15*time.Second, nil)
	assert.True(t, ok, "gathering works again after the abandoned one exited")
}

func TestInfoSource_CurrentExcludesAddresses(t *testing.T) {
	addrs := GetInfo(context.Background()).NetworkAddresses
	if len(addrs) == 0 {
		t.Skip("no network addresses on this host")
	}
	excluded := addrs[0].NetIP.Addr()
	matching := 0
	for _, addr := range addrs {
		if addr.NetIP.Addr() == excluded {
			matching++
		}
	}

	var src InfoSource
	info := src.Current(context.Background(), excluded)

	assert.Len(t, info.NetworkAddresses, len(addrs)-matching)
	for _, addr := range info.NetworkAddresses {
		assert.NotEqual(t, excluded, addr.NetIP.Addr())
	}
}
