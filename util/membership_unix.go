//go:build linux || darwin || freebsd

package util

import (
	"os"
)

// IsAdmin returns true if user is root
func IsAdmin() bool {
	return os.Geteuid() == 0
}
