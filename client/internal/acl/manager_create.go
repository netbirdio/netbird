//go:build !linux

package acl

import (
	"fmt"

	"runtime"
)

// Create creates a firewall manager instance
func Create(wgIfaceName string) (manager *DefaultManager, err error) {
	return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
}
