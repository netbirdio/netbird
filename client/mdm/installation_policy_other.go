//go:build !windows

package mdm

import "github.com/netbirdio/netbird/client/internal/instance"

// loadInstallationPlatform reads a named installation's own policy. Named
// installations exist only on Windows.
func loadInstallationPlatform(instance.Name) (map[string]any, error) {
	//nolint:nilnil // no source outside Windows
	return nil, nil
}
