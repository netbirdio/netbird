package stdnet

import (
	"regexp"
	"runtime"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// legacyDockerBridgePrefix shipped in DefaultInterfaceBlacklist to exclude Docker's
// user-defined network bridges. It is still recognised here because installations
// created before this change persisted it into their config, but it is no longer
// honoured as a prefix. See dockerBridgeName.
const legacyDockerBridgePrefix = "br-"

// dockerBridgeName matches the bridge names Docker derives from a user-defined
// network ID: "br-" followed by the first 12 hex characters of that ID.
//
// Excluding the bare "br-" prefix instead also excludes OpenWrt's br-lan, br-wan
// and br-guest, which are ordinary LAN interfaces. A router then has no host
// candidate for the network its own peers sit on, so those peers can only pair
// via server-reflexive candidates and fall back to the relay.
var dockerBridgeName = regexp.MustCompile(`^br-[0-9a-f]{12}$`)

// InterfaceFilter is a function passed to ICE Agent to filter out not allowed interfaces
// to avoid building tunnel over them. A nil detector probes the interface on every call,
// which is what the callers that build one filter for their whole lifetime want.
func InterfaceFilter(disallowList []string, detector *WGDetector) func(string) bool {
	var reported sync.Map

	// Gathering runs once per ICE agent, so the same interface is filtered many times
	// over a client's life. Report each one once per filter: enough to tell from a log
	// why an interface produced no candidate, without flooding it.
	reject := func(iFace, reason string) bool {
		if _, seen := reported.LoadOrStore(iFace, struct{}{}); !seen {
			log.Debugf("excluding %s from ICE candidate gathering: %s", iFace, reason)
		}
		return false
	}

	return func(iFace string) bool {
		if strings.HasPrefix(iFace, "lo") {
			// hardcoded loopback check to support already installed agents
			return reject(iFace, "loopback")
		}

		if runtime.GOOS != "ios" {
			if dockerBridgeName.MatchString(iFace) {
				return reject(iFace, "docker bridge")
			}

			for _, s := range disallowList {
				if s == legacyDockerBridgePrefix {
					continue
				}

				if strings.HasPrefix(iFace, s) {
					return reject(iFace, "matches disallow list entry "+s)
				}
			}
		}

		// look for unlisted WireGuard interfaces
		if detector.IsWireGuard(iFace) {
			return reject(iFace, "WireGuard interface")
		}

		return true
	}
}
