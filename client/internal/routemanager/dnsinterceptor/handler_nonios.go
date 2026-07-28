//go:build !ios

package dnsinterceptor

import log "github.com/sirupsen/logrus"

func waitForRouteSettlement(_ *log.Entry) {
	// No-op on non-iOS platforms: route changes are applied synchronously by
	// the kernel, so no settlement delay is needed before the DNS response
	// reaches the application. The delay is only required on iOS where
	// setTunnelNetworkSettings applies routes asynchronously.
}
