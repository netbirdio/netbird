package statemanager

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetDefaultStatePath returns the path to the state file based on the operating system
// It returns an empty string if the path cannot be determined.
func GetDefaultStatePath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird", "state.json")
	case "darwin", "linux":
		return "/var/lib/netbird/state.json"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return "/var/db/netbird/state.json"
	}

	return ""

}
