package version

import (
	"regexp"
	"runtime/debug"
	"strings"

	v "github.com/hashicorp/go-version"
)

// DevelopmentVersion is the value of NetbirdVersion() for non-release builds.
// Wire-format consumers (management server, dashboard) match against this
// string, so it must not change without coordinating those consumers.
const DevelopmentVersion = "development"

// CIVersionPrefix marks CI snapshot builds (e.g. "ci-7470fbdd"). Such builds
// are treated as development versions by IsDevelopmentVersion.
const CIVersionPrefix = "ci-"

// DevVersionPrefix marks dev snapshot builds (e.g. "dev-7470fbdd"). Such builds
// are treated as development versions by IsDevelopmentVersion.
const DevVersionPrefix = "dev-"

// will be replaced with the release version when using goreleaser
var version = DevelopmentVersion

var (
	VersionRegexp = regexp.MustCompile("^" + v.VersionRegexpRaw + "$")
	SemverRegexp  = regexp.MustCompile("^" + v.SemverRegexpRaw + "$")
)

// NetbirdVersion returns the Netbird version. For non-release builds the
// value is the literal DevelopmentVersion constant; the VCS revision is
// exposed separately via NetbirdCommit so the wire format stays stable.
func NetbirdVersion() string {
	return version
}

// NetbirdCommit returns the VCS revision (truncated to 12 chars) of the
// build, with a "-dirty" suffix when the working tree was modified.
// Returns an empty string when no build info is embedded (e.g. release
// builds compiled by goreleaser without -buildvcs).
func NetbirdCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	if revision == "" {
		return ""
	}

	if len(revision) > 12 {
		revision = revision[:12]
	}

	if modified {
		revision += "-dirty"
	}
	return revision
}

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

// IsDevelopmentVersion reports whether the given version string identifies
// a non-release / development build. It is the single source of truth for
// "is this a dev build" checks across the codebase; use it instead of
// comparing against the "development" literal or ad-hoc substring checks.
//
// Matches the bare DevelopmentVersion constant as well as any future
// extension such as "development-<sha>" or "development-<sha>-dirty", and
// CI/dev snapshot builds prefixed with "ci-" or "dev-", while excluding
// tagged prereleases like "v0.31.1-dev".
func IsDevelopmentVersion(v string) bool {
	return strings.HasPrefix(v, DevelopmentVersion) ||
		strings.HasPrefix(v, CIVersionPrefix) ||
		strings.HasPrefix(v, DevVersionPrefix)
}
