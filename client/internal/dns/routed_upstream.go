package dns

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// envRoutedUpstreamGating selects when an upstream nameserver that is only
// reachable through a routing peer may be configured. Accepted values are
// "off", "startup" and "always"; anything else falls back to "off".
const envRoutedUpstreamGating = "NB_DNS_ROUTED_UPSTREAM_GATING"

// routedUpstreamGating decides how long the "is there a route to this
// nameserver" check keeps influencing the configuration.
type routedUpstreamGating int

const (
	// gatingOff configures every nameserver group as soon as management
	// sends it, regardless of whether its upstreams are reachable.
	gatingOff routedUpstreamGating = iota
	// gatingStartup withholds a group until a route to its upstreams
	// exists for the first time, then keeps it configured for good. A
	// routing peer going away later does not withdraw the group.
	gatingStartup
	// gatingAlways re-evaluates continuously: a group is withdrawn again
	// when the route to its upstreams goes away.
	gatingAlways
)

func (g routedUpstreamGating) String() string {
	switch g {
	case gatingStartup:
		return "startup"
	case gatingAlways:
		return "always"
	default:
		return "off"
	}
}

func routedUpstreamGatingFromEnv() routedUpstreamGating {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envRoutedUpstreamGating))) {
	case "":
		return gatingOff
	case "off":
		return gatingOff
	case "startup":
		return gatingStartup
	case "always":
		return gatingAlways
	default:
		log.Warnf("invalid %s value %q, using %s", envRoutedUpstreamGating, os.Getenv(envRoutedUpstreamGating), gatingOff)
		return gatingOff
	}
}
