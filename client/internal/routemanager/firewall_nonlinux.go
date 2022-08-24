//go:build !linux
// +build !linux

package routemanager

import "context"

type unimplementedFirewall struct{}

func (unimplementedFirewall) RestoreOrCreateContainers() error {
	return nil
}
func (unimplementedFirewall) InsertRoutingRules(pair RouterPair) error {
	return nil
}
func (unimplementedFirewall) RemoveRoutingRules(pair RouterPair) error {
	return nil
}

func NewFirewall(parentCtx context.Context) firewallManager {
	return unimplementedFirewall{}
}
