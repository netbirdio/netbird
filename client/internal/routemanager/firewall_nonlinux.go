//go:build !linux
// +build !linux

package routemanager

import (
	"context"
	"fmt"
)

// NewFirewall returns a nil manager
func NewFirewall(context.Context) (firewallManager, error) {
	return nil, fmt.Errorf("firewall not supported on this OS")
}
