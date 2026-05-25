package version

import (
	"regexp"
	"strings"

	v "github.com/hashicorp/go-version"
)

// DevelopmentVersion is the value of NetbirdVersion() for non-release builds.
// Wire-format consumers (management server, dashboard) match against this
// string, so it must not change without coordinating those consumers.
const DevelopmentVersion = "development"

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

// IsDevelopmentVersion reports whether the given version string identifies
// a non-release / development build. It is the single source of truth for
// "is this a dev build" checks across the codebase; use it instead of
// comparing against the "development" literal or ad-hoc substring checks.
func IsDevelopmentVersion(v string) bool {
	return strings.Contains(v, "dev")
}
