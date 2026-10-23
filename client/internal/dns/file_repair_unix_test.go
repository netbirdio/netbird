//go:build (linux && !android) || freebsd

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/util"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("debug", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

func Test_newRepairtmp(t *testing.T) {
	type args struct {
		resolvConfContent  string
		touchedConfContent string
		wantChange         bool
	}
	tests := []args{
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 8.8.8.8
searchdomain netbird.cloud something`,
			wantChange: true,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something somethingelse`,
			wantChange: false,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 10.0.0.1
searchdomain netbird.cloud something`,
			wantChange: false,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
searchdomain something`,
			wantChange: true,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 10.0.0.1`,
			wantChange: true,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 8.8.8.8`,
			wantChange: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			workDir := t.TempDir()
			operationFile := workDir + "/resolv.conf"
			err := os.WriteFile(operationFile, []byte(tt.resolvConfContent), 0755)
			if err != nil {
				t.Fatalf("failed to write out resolv.conf: %s", err)
			}

			var changed bool
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			updateFn := func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error) {
				changed = true
				cancel()
				return nil, nil
			}

			r := newRepair(operationFile, updateFn)
			r.watchFileChanges([]string{"netbird.cloud"}, netip.MustParseAddr("10.0.0.1"), nil, nil)

			err = os.WriteFile(operationFile, []byte(tt.touchedConfContent), 0755)
			if err != nil {
				t.Fatalf("failed to write out resolv.conf: %s", err)
			}

			<-ctx.Done()

			r.stopWatchFileChanges()

			if changed != tt.wantChange {
				t.Errorf("unexpected result: want: %v, got: %v", tt.wantChange, changed)
			}
		})
	}
}

func Test_newRepairSymlink(t *testing.T) {
	resolvConfContent := `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`

	modifyContent := `nameserver 8.8.8.8`

	tmpResolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	err := os.WriteFile(tmpResolvConf, []byte(resolvConfContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	tmpLink := filepath.Join(t.TempDir(), "symlink")
	err = os.Symlink(tmpResolvConf, tmpLink)
	if err != nil {
		t.Fatal(err)
	}

	var changed bool
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	updateFn := func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error) {
		changed = true
		cancel()
		return nil, nil
	}

	r := newRepair(tmpLink, updateFn)
	r.watchFileChanges([]string{"netbird.cloud"}, netip.MustParseAddr("10.0.0.1"), nil, nil)

	err = os.WriteFile(tmpLink, []byte(modifyContent), 0755)
	if err != nil {
		t.Fatalf("failed to write out resolv.conf: %s", err)
	}

	<-ctx.Done()

	r.stopWatchFileChanges()

	if changed != true {
		t.Errorf("unexpected result: want: %v, got: %v", true, false)
	}
}

// systemd-resolved can rewrite resolv.conf twice in a row, e.g. on restart. When the second write
// lands right after NetBird's repair, the watcher must still see it and repair again; otherwise the
// host silently stays on the upstream resolver until the next unrelated change of the file.
func Test_repairCatchesWriteRacingRepair(t *testing.T) {
	good := "nameserver 10.0.0.1\nsearch netbird.cloud\n"
	upstream := "nameserver 8.8.8.8\nsearch .\n"
	operationFile := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(operationFile, []byte(good), 0644))

	var calls atomic.Int32
	updateFn := func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error) {
		n := calls.Add(1)
		if err := os.WriteFile(operationFile, []byte(good), 0644); err != nil {
			return nil, err
		}
		if n == 1 {
			// the third party's second write lands right after the repair
			if err := writeFileAtomic(operationFile, upstream); err != nil {
				return nil, err
			}
		}
		return []byte(good), nil
	}

	r := newRepair(operationFile, updateFn)
	r.watchFileChanges([]string{"netbird.cloud"}, netip.MustParseAddr("10.0.0.1"), []byte(good), nil)
	t.Cleanup(r.stopWatchFileChanges)

	require.NoError(t, writeFileAtomic(operationFile, upstream))

	assert.Eventually(t, func() bool {
		content, err := os.ReadFile(operationFile)
		return err == nil && string(content) == good
	}, 2*time.Second, 10*time.Millisecond, "resolv.conf should be repaired after the racing write")
	assert.GreaterOrEqual(t, calls.Load(), int32(2), "the racing write should trigger a second repair")
}

// A change made between NetBird's write and the arming of the watch produces no event, so the
// watcher must check the file as soon as it starts.
func Test_repairChecksFileWhenArmed(t *testing.T) {
	good := "nameserver 10.0.0.1\nsearch netbird.cloud\n"
	operationFile := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(operationFile, []byte("nameserver 8.8.8.8\n"), 0644))

	repaired := make(chan struct{}, 1)
	updateFn := func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error) {
		select {
		case repaired <- struct{}{}:
		default:
		}
		return []byte(good), os.WriteFile(operationFile, []byte(good), 0644)
	}

	r := newRepair(operationFile, updateFn)
	r.watchFileChanges([]string{"netbird.cloud"}, netip.MustParseAddr("10.0.0.1"), []byte(good), nil)
	t.Cleanup(r.stopWatchFileChanges)

	select {
	case <-repaired:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher should repair a file changed before it was armed")
	}
}

// When NetBird has more search domains than resolv.conf can hold, its own write lacks some of them
// and fails the parameter check. The watcher must recognize that write as its own and not repair
// it again in a loop.
func Test_repairNoLoopOnTruncatedSearchDomains(t *testing.T) {
	nbDomains := make([]string, 0, fileMaxNumberOfSearchDomains+2)
	for i := range fileMaxNumberOfSearchDomains + 2 {
		nbDomains = append(nbDomains, fmt.Sprintf("d%d.netbird.cloud", i))
	}
	truncated := fmt.Sprintf("nameserver 10.0.0.1\nsearch %s\n", strings.Join(nbDomains[:fileMaxNumberOfSearchDomains], " "))

	operationFile := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(operationFile, []byte(truncated), 0644))

	var calls atomic.Int32
	updateFn := func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error) {
		calls.Add(1)
		return []byte(truncated), os.WriteFile(operationFile, []byte(truncated), 0644)
	}

	r := newRepair(operationFile, updateFn)
	r.watchFileChanges(nbDomains, netip.MustParseAddr("10.0.0.1"), []byte(truncated), nil)
	t.Cleanup(r.stopWatchFileChanges)

	require.NoError(t, writeFileAtomic(operationFile, "nameserver 8.8.8.8\n"))

	require.Eventually(t, func() bool { return calls.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"the third-party write should be repaired")
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(1), calls.Load(), "NetBird's own truncated write should not trigger another repair")
}

// fsnotify blocks its reader until an error is received, and an error such as a queue overflow
// means events were dropped. The watcher must consume errors and check the file, so it keeps working
// and catches a change whose event was lost.
func Test_repairChecksFileOnWatcherError(t *testing.T) {
	good := "nameserver 10.0.0.1\nsearch netbird.cloud\n"
	operationFile := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(operationFile, []byte(good), 0644))

	// A hard link in another directory changes the file without an event in the watched one,
	// standing in for an event the kernel dropped.
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Link(operationFile, alias))

	repaired := make(chan struct{}, 1)
	updateFn := func([]string, netip.Addr, *resolvConf, *statemanager.Manager) ([]byte, error) {
		select {
		case repaired <- struct{}{}:
		default:
		}
		return []byte(good), os.WriteFile(operationFile, []byte(good), 0644)
	}

	r := newRepair(operationFile, updateFn)
	r.watchFileChanges([]string{"netbird.cloud"}, netip.MustParseAddr("10.0.0.1"), []byte(good), nil)
	t.Cleanup(r.stopWatchFileChanges)

	require.NoError(t, os.WriteFile(alias, []byte("nameserver 8.8.8.8\n"), 0644))

	select {
	case r.inotify.Errors <- fsnotify.ErrEventOverflow:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher should consume inotify errors")
	}

	select {
	case <-repaired:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher should check the file after an inotify error")
	}
}

// writeFileAtomic replaces the file the way systemd-resolved does: write a temporary file in the same
// directory, then rename it over the target.
func writeFileAtomic(target, content string) error {
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}
