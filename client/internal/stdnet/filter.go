package stdnet

import (
	"runtime"
	"strings"
)

// InterfaceFilter is a function passed to ICE Agent to filter out not allowed interfaces
// to avoid building tunnel over them. A nil detector probes the interface on every call,
// which is what the callers that build one filter for their whole lifetime want.
func InterfaceFilter(disallowList []string, detector *WGDetector) func(string) bool {
	return func(iFace string) bool {
		if strings.HasPrefix(iFace, "lo") {
			// hardcoded loopback check to support already installed agents
			return false
		}

		for _, s := range disallowList {
			if strings.HasPrefix(iFace, s) && runtime.GOOS != "ios" {
				return false
			}
		}

		// look for unlisted WireGuard interfaces
		return !detector.IsWireGuard(iFace)
	}
}
