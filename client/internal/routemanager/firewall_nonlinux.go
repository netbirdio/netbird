//go:build !linux
// +build !linux

package routemanager

import "context"

// newFirewall returns an unimplemented Firewall manager
func newFirewall(parentCtx context.Context) firewallManager {
	return unimplementedFirewall{}
}
