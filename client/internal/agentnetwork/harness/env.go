package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// UserEnv resolves paths for the user running this process, keeping the
// ownership record next to the user's NetBird config.
func UserEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("find home directory: %w", err)
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Env{}, fmt.Errorf("find config directory: %w", err)
	}
	return Env{
		GOOS:       runtime.GOOS,
		Home:       home,
		Getenv:     os.Getenv,
		RecordPath: filepath.Join(cfg, "netbird", "agent-network-setup.json"),
	}, nil
}

// Uses reports whether any key of the variant references the placeholder.
func (v Variant) Uses(name Var) bool {
	for _, k := range v.Keys {
		for _, m := range placeholder.FindAllStringSubmatch(k.Value, -1) {
			if Var(m[1]) == name {
				return true
			}
		}
	}
	return false
}
