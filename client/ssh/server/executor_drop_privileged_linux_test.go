//go:build linux && privileged

package server

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envDropPrivilegesChild = "NB_TEST_DROP_PRIVILEGES_CHILD"

const (
	dropTargetUID = 65534
	dropTargetGID = 65534
	dropExtraGID  = 65533
)

// TestDropPrivilegesAllThreads drops privileges in a child process, because the drop
// cannot be undone, and checks that every OS thread of that process carries the target
// credentials. A drop applied to the calling thread only would leave the others as root.
func TestDropPrivilegesAllThreads(t *testing.T) {
	if os.Getenv(envDropPrivilegesChild) == "1" {
		dropPrivilegesChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDropPrivilegesAllThreads$", "-test.v")
	cmd.Env = append(os.Environ(), envDropPrivilegesChild+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	require.NoError(t, err, "child must drop privileges on all threads")
	assert.Contains(t, string(out), "--- PASS: TestDropPrivilegesAllThreads", "child test must run and pass")
}

func dropPrivilegesChild(t *testing.T) {
	// Park goroutines on their own OS threads so the process has threads other than
	// the one that performs the drop.
	release := make(chan struct{})
	defer close(release)
	ready := make(chan struct{})
	for range 4 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-release
		}()
		<-ready
	}

	pd := NewPrivilegeDropper()
	require.NoError(t, pd.DropPrivileges(dropTargetUID, dropTargetGID, []uint32{dropTargetGID, dropExtraGID}))

	tasks, err := filepath.Glob("/proc/self/task/*/status")
	require.NoError(t, err)
	require.Greater(t, len(tasks), 4, "process must have several threads for the check to mean anything")

	want := map[string]string{
		"Uid":    fmt.Sprintf("%d\t%d\t%d\t%d", dropTargetUID, dropTargetUID, dropTargetUID, dropTargetUID),
		"Gid":    fmt.Sprintf("%d\t%d\t%d\t%d", dropTargetGID, dropTargetGID, dropTargetGID, dropTargetGID),
		"Groups": fmt.Sprintf("%d %d", dropExtraGID, dropTargetGID),
	}
	for _, task := range tasks {
		got := readStatusFields(t, task)
		for field, value := range want {
			assert.Equal(t, value, got[field], "%s of %s", field, task)
		}
	}

	assert.Error(t, seteuid(0), "euid 0 must not be restorable after the drop")
	assert.Error(t, setegid(0), "egid 0 must not be restorable after the drop")
}

func readStatusFields(t *testing.T, path string) map[string]string {
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	fields := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields[key] = strings.TrimSpace(value)
	}
	require.NoError(t, scanner.Err())
	return fields
}
