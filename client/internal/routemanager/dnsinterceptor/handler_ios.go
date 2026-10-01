//go:build ios

package dnsinterceptor

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const routeSettleDelay = 500 * time.Millisecond

// waitForRouteSettlement introduces a short delay on iOS to allow
// setTunnelNetworkSettings to apply route changes before the DNS
// response reaches the application. Without this, the first request
// to a newly resolved domain may bypass the tunnel.
func waitForRouteSettlement(logger *log.Entry) {
	logger.Tracef("waiting %v for iOS route settlement", routeSettleDelay)
	time.Sleep(routeSettleDelay)
}
