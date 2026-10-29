package version

import (
	"strings"

	v "github.com/hashicorp/go-version"
)

// sanitizeVersion removes anything after the pre-release tag (e.g., "-dev", "-alpha", etc.)
func sanitizeVersion(version string) string {
	parts := strings.Split(version, "-")
	return parts[0]
}

// MeetsMinVersion checks if the peer's version meets or exceeds the minimum required version
func MeetsMinVersion(minVer, peerVer string) (bool, error) {
	peerVer = sanitizeVersion(peerVer)
	minVer = sanitizeVersion(minVer)

	peerNBVer, err := v.NewVersion(peerVer)
	if err != nil {
		return false, err
	}

	constraints, err := v.NewConstraint(">= " + minVer)
	if err != nil {
		return false, err
	}

	return constraints.Check(peerNBVer), nil
}
