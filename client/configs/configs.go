package configs

import (
	"os"
	"path/filepath"
	"runtime"
)

var StateDir string

func init() {
	StateDir = os.Getenv("NB_STATE_DIR")
	if StateDir != "" {
		return
	}
	switch runtime.GOOS {
	case "windows":
		StateDir = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird")
	case "darwin", "linux":
		StateDir = "/var/lib/netbird"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		StateDir = "/var/db/netbird"
	}
}
