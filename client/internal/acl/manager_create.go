//go:build !linux

package acl

import (
	"fmt"
	"runtime"

	"github.com/netbirdio/netbird/client/firewall"
)

// Create creates a firewall controller instance
func Create(wgIfaceName string) (controller *Controller, err error) {
	return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
}
