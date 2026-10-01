//go:build ios

package NetBirdSDK

import "github.com/netbirdio/netbird/version"

// GoClientVersion returns the NetBird Go client version that was baked into
// the framework at compile time via
// -ldflags "-X github.com/netbirdio/netbird/version.version=<version>".
func GoClientVersion() string {
	return version.NetbirdVersion()
}
