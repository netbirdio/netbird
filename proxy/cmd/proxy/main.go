package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"

	"github.com/netbirdio/netbird/proxy"
)

const DefaultManagementURL = "https://api.netbird.io:443"

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

func envBoolOrDefault(key string, def bool) bool {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	return v == strings.ToLower("true")
}

func envStringOrDefault(key string, def string) string {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	return v
}

func main() {
	var (
		version, debug, acmeCerts                  bool
		mgmtAddr, addr, certDir, acmeAddr, acmeDir string
	)

	flag.BoolVar(&version, "v", false, "Print version and exit")
	flag.BoolVar(&debug, "debug", envBoolOrDefault("NB_PROXY_DEBUG_LOGS", false), "Enable debug logs")
	flag.StringVar(&mgmtAddr, "mgmt", envStringOrDefault("NB_PROXY_MANAGEMENT_ADDRESS", DefaultManagementURL), "Management address to connect to.")
	flag.StringVar(&addr, "addr", envStringOrDefault("NB_PROXY_ADDRESS", ":443"), "Reverse proxy address to listen on.")
	flag.StringVar(&certDir, "cert-dir", envStringOrDefault("NB_PROXY_CERTIFICATE_DIRECTORY", "./certs"), "Directory to store ")
	flag.BoolVar(&acmeCerts, "acme-certs", envBoolOrDefault("NB_PROXY_ACME_CERTIFICATES", false), "Generate ACME certificates using HTTP-01 challenges.")
	flag.StringVar(&acmeAddr, "acme-addr", envStringOrDefault("NB_PROXY_ACME_ADDRESS", ":80"), "HTTP address to listen on, used for ACME HTTP-01 certificate generation.")
	flag.StringVar(&acmeDir, "acme-dir", envStringOrDefault("NB_PROXY_ACME_DIRECTORY", acme.LetsEncryptURL), "URL of ACME challenge directory.")
	flag.Parse()

	if version {
		fmt.Printf("Version: %s, Commit: %s, BuildDate: %s, Go: %s", Version, Commit, BuildDate, GoVersion)
		os.Exit(0)
	}

	// Configure logrus.
	level := "error"
	if debug {
		level = "debug"
	}

	_ = util.InitLog(level, util.LogConsole)

	log.Infof("configured log level: %s", level)

	srv := proxy.Server{
		Version:                  Version,
		ManagementAddress:        mgmtAddr,
		CertificateDirectory:     certDir,
		GenerateACMECertificates: acmeCerts,
		ACMEChallengeAddress:     acmeAddr,
		ACMEDirectory:            acmeDir,
	}

	if err := srv.ListenAndServe(context.TODO(), addr); err != nil {
		log.Fatal(err)
	}
}
