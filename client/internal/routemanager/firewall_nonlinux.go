//go:build !linux
// +build !linux

package routemanager

import "context"

type unimplementedFirewall struct{}

func (unimplementedFirewall) RestoreOrCreateContainers() error {
	return nil
}
func (unimplementedFirewall) InsertRoutingRules(pair routerPair) error {
	return nil
}
func (unimplementedFirewall) RemoveRoutingRules(pair routerPair) error {
	return nil
}

func (unimplementedFirewall) CleanRoutingRules() {
	return
}

// NewFirewall returns an unimplemented Firewall manager
func NewFirewall(parentCtx context.Context) firewallManager {
	return unimplementedFirewall{}
}
