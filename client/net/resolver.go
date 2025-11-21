package net

import (
	"net"
	"os"
	"runtime"
	"strings"
)

const (
	// EnvResolver is the environment variable to control DNS resolver behavior
	// Values: "system" (use system resolver), "go" (use pure Go resolver), empty (auto-detect)
	EnvResolver = "NB_DNS_RESOLVER"
)

// NewResolver creates a DNS resolver with appropriate settings based on platform and configuration.
// On Darwin (macOS), it defaults to the pure Go resolver to avoid getaddrinfo hangs after sleep/wake.
// This is particularly important for connections using this package's Dialer, which bypasses the NetBird
// overlay network for control plane traffic. Since these connections target external infrastructure
// (management, signal, relay servers), it is safe to ignore split DNS configurations that would
// normally be provided by the system resolver.
// On other platforms, it uses the system resolver (cgo).
// This behavior can be overridden using the NB_DNS_RESOLVER environment variable or GODEBUG.
func NewResolver() *net.Resolver {
	if resolver := os.Getenv(EnvResolver); resolver != "" {
		switch strings.ToLower(resolver) {
		case "system":
			return net.DefaultResolver
		case "go":
			return &net.Resolver{
				PreferGo: true,
			}
		}
	}

	if runtime.GOOS == "darwin" {
		return &net.Resolver{
			PreferGo: true,
		}
	}

	return net.DefaultResolver
}
