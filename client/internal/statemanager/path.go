package statemanager

import (
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// GetDefaultStatePath returns the path to the state file based on the operating system
// It returns an empty string if the path cannot be determined. It also creates the directory if it does not exist.
func GetDefaultStatePath() string {
	var path string

	switch runtime.GOOS {
	case "windows":
		path = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird", "state.json")
	case "darwin", "linux":
		path = "/var/lib/netbird/state.json"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		path = "/var/db/netbird/state.json"
	// ios/android don't need state
	default:
		return ""
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Errorf("Error creating directory %s: %v. Continuing without state support.", dir, err)
		return ""
	}

	return path
}
