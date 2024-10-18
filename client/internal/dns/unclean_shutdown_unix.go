//go:build (linux && !android) || freebsd

package dns

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type ShutdownState struct {
	ManagerType osManagerType
	DNSAddress  netip.Addr
	WgIface     string
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	manager, err := newHostManagerFromType(s.WgIface, s.ManagerType)
	if err != nil {
		return fmt.Errorf("create previous host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownDNS(&s.DNSAddress); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}

// TODO: move file contents to state manager
func createUncleanShutdownIndicator(sourcePath string, dnsAddressStr string, stateManager *statemanager.Manager) error {
	dnsAddress, err := netip.ParseAddr(dnsAddressStr)
	if err != nil {
		return fmt.Errorf("parse dns address %s: %w", dnsAddressStr, err)
	}

	dir := filepath.Dir(fileUncleanShutdownResolvConfLocation)
	if err := os.MkdirAll(dir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	if err := copyFile(sourcePath, fileUncleanShutdownResolvConfLocation); err != nil {
		return fmt.Errorf("create %s: %w", sourcePath, err)
	}

	state := &ShutdownState{
		ManagerType: fileManager,
		DNSAddress:  dnsAddress,
	}
	if err := stateManager.UpdateState(state); err != nil {
		return fmt.Errorf("update state: %w", err)
	}

	return nil
}
