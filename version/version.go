package version

// will be replaced with the release version when using goreleaser
var version = "development"

// NetbirdVersion returns the Netbird version
func NetbirdVersion() string {
	return version
}
