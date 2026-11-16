package system

import (
	"context"
	"net/netip"
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
	src.abandoned = map[uint64]time.Time{1: time.Now()}

	_, ok := src.Refresh(context.Background(), 15*time.Second, nil)
	assert.False(t, ok, "no gathering starts while an earlier one is still running")

	src.abandoned = nil
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

	require.Eventually(t, func() bool { return src.abandonedCount() == 0 }, 10*time.Second, 10*time.Millisecond,
		"the source is released when the abandoned gathering exits")
	_, ok = src.Refresh(context.Background(), 15*time.Second, nil)
	assert.True(t, ok, "gathering works again after the abandoned one exited")
}

// stubGathering replaces the gathering with one that reports a single file check for the
// path the checks name, and blocks a gathering for blockedPath until release is closed.
// entered receives once that gathering has started.
func stubGathering(t *testing.T, blockedPath string) (entered chan struct{}, release chan struct{}) {
	t.Helper()
	entered = make(chan struct{}, 1)
	release = make(chan struct{})
	original := gatherInfoWithChecks
	gatherInfoWithChecks = func(_ context.Context, checks []*proto.Checks, _ ...netip.Addr) (*Info, error) {
		path := checks[0].Files[0]
		if path == blockedPath {
			entered <- struct{}{}
			<-release
		}
		return &Info{Files: []File{{Path: path, Exist: true}}}, nil
	}
	t.Cleanup(func() { gatherInfoWithChecks = original })
	return entered, release
}

func filesCheck(path string) []*proto.Checks {
	return []*proto.Checks{{Files: []string{path}}}
}

// TestInfoSource_RefreshRunsConcurrently: only a gathering that timed out holds off new
// ones; a caller gathering while another gathering is in progress is served.
func TestInfoSource_RefreshRunsConcurrently(t *testing.T) {
	entered, release := stubGathering(t, "/slow")
	var src InfoSource

	slowDone := make(chan bool, 1)
	go func() {
		_, ok := src.Refresh(context.Background(), 15*time.Second, filesCheck("/slow"))
		slowDone <- ok
	}()
	<-entered

	_, ok := src.Refresh(context.Background(), 15*time.Second, filesCheck("/fast"))
	assert.True(t, ok, "a gathering runs while another one is still in progress")

	close(release)
	assert.True(t, <-slowDone, "the slower gathering completes too")
}

// TestInfoSource_LateOlderRefreshDoesNotReplaceNewerResults: a Refresh for the previous
// checks that finishes after one for the current checks must not bring back the old
// results Current reports.
func TestInfoSource_LateOlderRefreshDoesNotReplaceNewerResults(t *testing.T) {
	entered, release := stubGathering(t, "/old")
	var src InfoSource

	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		_, _ = src.Refresh(context.Background(), 15*time.Second, filesCheck("/old"))
	}()
	<-entered

	_, ok := src.Refresh(context.Background(), 15*time.Second, filesCheck("/new"))
	require.True(t, ok)
	close(release)
	<-oldDone

	files := src.Current(context.Background()).Files
	require.Len(t, files, 1)
	assert.Equal(t, "/new", files[0].Path, "the results of the refresh that started last are kept")
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

// TestInfoSource_LostGatheringDoesNotBlockForever: a gathering blocked for good, such as
// an os.Stat on a dead network mount, must not stop every later meta sync. Once it has
// run for lostAfter timeouts another starts beside it, and no more than maxAbandoned
// are ever left running.
func TestInfoSource_LostGatheringDoesNotBlockForever(t *testing.T) {
	entered, release := stubGathering(t, "/wedged")
	t.Cleanup(func() { close(release) })
	now := time.Now()
	src := InfoSource{now: func() time.Time { return now }}
	const timeout = 10 * time.Millisecond
	lost := time.Duration(infoLostAfter) * timeout

	_, ok := src.Refresh(context.Background(), timeout, filesCheck("/wedged"))
	require.False(t, ok, "the wedged gathering times out")
	<-entered

	_, ok = src.Refresh(context.Background(), timeout, filesCheck("/wedged"))
	assert.False(t, ok, "a gathering that may still finish holds off the next one")

	now = now.Add(lost)
	_, ok = src.Refresh(context.Background(), timeout, filesCheck("/wedged"))
	require.False(t, ok, "the second wedged gathering times out too")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("once the first gathering is lost another one starts")
	}

	now = now.Add(lost)
	_, ok = src.Refresh(context.Background(), timeout, filesCheck("/wedged"))
	assert.False(t, ok, "no more than maxAbandoned gatherings are left running")
	select {
	case <-entered:
		t.Fatal("a third gathering started beside two lost ones")
	case <-time.After(50 * time.Millisecond):
	}
}
