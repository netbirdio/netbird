package dnsfw

import (
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvDisable disables the DNS firewall entirely when set to a truthy value.
	EnvDisable = "NB_DISABLE_DNS_FIREWALL"
	// EnvPorts overrides the comma-separated list of remote ports to block.
	// Empty disables the firewall.
	EnvPorts = "NB_DNS_FIREWALL_PORTS"
	// EnvStrict enables strict mode: permit DNS only to the virtual DNS IP
	// and the netbird daemon. Default mode also permits anything on the
	// netbird tunnel interface, which is safer if NRPT is silently ignored
	// by Windows but lets apps reach custom DNS servers via the tunnel.
	EnvStrict = "NB_DNS_FIREWALL_STRICT"
)

// defaultBlockedPorts are the well-known DNS ports we block for non-netbird
// processes: 53 (plain DNS) and 853 (DNS-over-TLS).
var defaultBlockedPorts = []uint16{53, 853}

// blockedPorts returns the effective port list, honoring env overrides.
// A nil return means the firewall should not be installed.
func blockedPorts() []uint16 {
	if disabled, _ := strconv.ParseBool(os.Getenv(EnvDisable)); disabled {
		log.Infof("dns firewall disabled via %s", EnvDisable)
		return nil
	}

	override, ok := os.LookupEnv(EnvPorts)
	if !ok {
		return defaultBlockedPorts
	}

	var ports []uint16
	for _, raw := range strings.Split(override, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		port, err := strconv.ParseUint(raw, 10, 16)
		if err != nil {
			log.Warnf("dns firewall: ignoring invalid port %q in %s: %v", raw, EnvPorts, err)
			continue
		}
		if port == 0 {
			log.Warnf("dns firewall: ignoring port 0 in %s", EnvPorts)
			continue
		}
		ports = append(ports, uint16(port))
	}
	if len(ports) == 0 {
		log.Infof("dns firewall disabled: %s yielded no valid ports", EnvPorts)
		return nil
	}
	return ports
}
