package configs

import (
	"os"
	"path/filepath"
	"runtime"
)

var (
	// StateDir holds persistent state (config, profiles, install metadata).
	StateDir string
	// RuntimeDir holds ephemeral artifacts that should not survive reboot,
	// such as Unix sockets for daemon and per-session IPC. Empty on
	// platforms without a conventional /var/run-style location.
	RuntimeDir string
)

func init() {
	switch runtime.GOOS {
	case "windows":
		StateDir = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird")
	case "darwin", "linux":
		StateDir = "/var/lib/netbird"
		RuntimeDir = "/var/run/netbird"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		StateDir = "/var/db/netbird"
		RuntimeDir = "/var/run/netbird"
	}
	if v := os.Getenv("NB_STATE_DIR"); v != "" {
		StateDir = v
	}
	if v := os.Getenv("NB_RUNTIME_DIR"); v != "" {
		RuntimeDir = v
	}
}
