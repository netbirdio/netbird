//go:build !windows

package daemonaddr

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A socket this user created means the daemon runs as this user, which is the
// rootless case where the daemon delegates its authority to its own identity.
func TestDaemonRunsAsSelf_OwnSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netbird.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Logf("close listener: %v", err)
		}
	})

	if !DaemonRunsAsSelf("unix://" + path) {
		t.Error("a socket owned by this user must count as the daemon running as us")
	}
}

// Everything that is not a readable socket of ours has to answer false, because
// the caller reads a true as "the daemon would authorize me".
func TestDaemonRunsAsSelf_FailsClosed(t *testing.T) {
	dir := t.TempDir()

	// A socket owned by another user, which is what a root-run daemon looks like
	// to an unprivileged client. Only assertable when we are not root ourselves.
	rootOwned := "unix:///var/run/netbird.sock"
	if _, err := os.Stat("/var/run/netbird.sock"); err == nil && os.Getuid() != 0 {
		if DaemonRunsAsSelf(rootOwned) {
			t.Error("a socket owned by another user must not count as ours")
		}
	}

	for name, addr := range map[string]string{
		"missing socket":  "unix://" + filepath.Join(dir, "absent.sock"),
		"tcp address":     "tcp://127.0.0.1:41731",
		"named pipe":      "npipe://netbird",
		"empty":           "",
		"no scheme":       filepath.Join(dir, "absent.sock"),
		"directory":       "unix://" + dir,
		"unknown scheme":  "http://localhost:8080",
		"scheme only":     "unix://",
		"relative socket": "unix://netbird.sock",
	} {
		t.Run(name, func(t *testing.T) {
			if DaemonRunsAsSelf(addr) {
				t.Errorf("%q must not count as a daemon running as us", addr)
			}
		})
	}
}
