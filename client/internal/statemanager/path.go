package statemanager

import (
	"github.com/netbirdio/netbird/client/configs"
	"os"
	"path/filepath"
)

// GetDefaultStatePath returns the path to the state file based on the operating system
// It returns an empty string if the path cannot be determined.
func GetDefaultStatePath() string {
	if path := os.Getenv("NB_DNS_STATE_FILE"); path != "" {
		return path
	}
	return filepath.Join(configs.StateDir, "state.json")
}
