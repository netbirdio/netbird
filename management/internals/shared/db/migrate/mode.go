package migrate

import (
	"fmt"
	"os"
	"strings"
)

// Mode selects what the runner does with a database before the service serves.
type Mode string

const (
	// ModeAuto applies pending migrations under a lock and continues.
	ModeAuto Mode = "auto"
	// ModeCheck refuses to continue while migrations are pending and never changes the schema.
	ModeCheck Mode = "check"
	// ModeSkip opens the database without consulting the version table.
	ModeSkip Mode = "skip"

	// ModeEnv overrides the configured mode for every migration set of the process.
	ModeEnv = "NB_STORE_MIGRATION_MODE"
)

// ParseMode maps a configuration value to a Mode; the empty string means ModeAuto.
func ParseMode(value string) (Mode, error) {
	switch mode := Mode(strings.ToLower(strings.TrimSpace(value))); mode {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeCheck, ModeSkip:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown migration mode %q, expected %s, %s or %s", value, ModeAuto, ModeCheck, ModeSkip)
	}
}

// ResolveMode returns the mode set through ModeEnv, falling back to the configured value.
func ResolveMode(configured string) (Mode, error) {
	if env := os.Getenv(ModeEnv); env != "" {
		return ParseMode(env)
	}
	return ParseMode(configured)
}
