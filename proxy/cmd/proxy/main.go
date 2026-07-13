package main

import (
	"net/http"
	// nolint:gosec
	_ "net/http/pprof"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/cmd/proxy/cmd"
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

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	cmd.SetVersionInfo(Version, Commit, BuildDate, GoVersion)
	cmd.Execute()
}
