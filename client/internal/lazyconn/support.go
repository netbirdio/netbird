package lazyconn

import (
	"strings"

	"github.com/hashicorp/go-version"
)

var (
	minVersion = version.Must(version.NewVersion("0.45.0"))
)

func IsSupported(agentVersion string) bool {
	if agentVersion == "development" {
		return true
	}

	// Custom dev/CI builds tagged like "dev-089a95a" or "ci-abcdef" by
	// build-android-lib.sh / scripts/build_*.sh come from the same source
	// tree as the "development" build above; assume they support lazy.
	// Only the random short-hash form (e.g. "a6c5960") lacks any prefix
	// signal -- those still get rejected below.
	if strings.HasPrefix(agentVersion, "dev-") || strings.HasPrefix(agentVersion, "ci-") {
		return true
	}

	// filter out versions like this: a6c5960, a7d5c522, d47be154
	if !strings.Contains(agentVersion, ".") {
		return false
	}

	normalizedVersion := normalizeVersion(agentVersion)
	inputVer, err := version.NewVersion(normalizedVersion)
	if err != nil {
		return false
	}

	return inputVer.GreaterThanOrEqual(minVersion)
}

func normalizeVersion(version string) string {
	// Remove prefixes like 'v' or 'a'
	if len(version) > 0 && (version[0] == 'v' || version[0] == 'a') {
		version = version[1:]
	}

	// Remove any suffixes like '-dirty', '-dev', '-SNAPSHOT', etc.
	parts := strings.Split(version, "-")
	return parts[0]
}
