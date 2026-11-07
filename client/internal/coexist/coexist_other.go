//go:build !windows

package coexist

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// OtherOverlayRoutes returns the routes on other NetBird adapters. Named
// installations exist only on Windows, so there are none elsewhere.
func OtherOverlayRoutes(string) ([]netip.Prefix, error) {
	return nil, nil
}

// OtherPrimary names another primary installation; only Windows has more than
// one installation.
func OtherPrimary(instance.Instance) (string, bool) {
	return "", false
}
