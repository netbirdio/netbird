package main

import (
	"net/http"
	// nolint:gosec
	_ "net/http/pprof"
	"os"
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
	if pprofAddr := os.Getenv("NB_PPROF_ADDR"); pprofAddr != "" {
		log.Infof("pprof enabled, listening on: %s", pprofAddr)
		go func() {
			log.Println(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	cmd.SetVersionInfo(Version, Commit, BuildDate, GoVersion)
	cmd.Execute()
}
