//go:build !linux || android

package server

import (
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/ssh/config"
)

// registerStates registers all states that need crash recovery cleanup.
// Note: portforward.State is intentionally NOT registered here to avoid blocking startup
// for up to 10 seconds during NAT gateway discovery when no gateway is present.
// The gateway reference cannot be persisted across restarts, so cleanup requires re-discovery.
// Port forward cleanup is handled by the Manager during normal operation instead.
func registerStates(mgr *statemanager.Manager) {
	mgr.RegisterState(&dns.ShutdownState{})
	mgr.RegisterState(&systemops.ShutdownState{})
	mgr.RegisterState(&config.ShutdownState{})
}
