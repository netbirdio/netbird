//go:build ios

package NetBirdSDK

import "github.com/netbirdio/netbird/version"

// GoClientVersion returns the NetBird Go client version that was baked into
// the framework at compile time via
// -ldflags "-X github.com/netbirdio/netbird/version.version=<version>".
func GoClientVersion() string {
	return version.NetbirdVersion()
}

// GoClientCommit returns the VCS revision of the Go client build, or an empty
// string when no build info is embedded.
func GoClientCommit() string {
	return version.NetbirdCommit()
}
