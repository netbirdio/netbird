package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the application version (set via ldflags during build)
	Version = "dev"

	// Commit is the git commit hash (set via ldflags during build)
	Commit = "unknown"

	// BuildDate is the build date (set via ldflags during build)
	BuildDate = "unknown"

	// GoVersion is the Go version used to build the binary
	GoVersion = runtime.Version()
)

// Info contains version information
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the version information
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: GoVersion,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a formatted version string
func String() string {
	return fmt.Sprintf("Version: %s, Commit: %s, BuildDate: %s, Go: %s",
		Version, Commit, BuildDate, GoVersion)
}

// Short returns a short version string
func Short() string {
	if Version == "dev" {
		return fmt.Sprintf("%s (%s)", Version, Commit[:7])
	}
	return Version
}
