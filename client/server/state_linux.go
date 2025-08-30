//go:build !android

package server

import (
	"github.com/netbirdio/netbird/client/firewall/iptables"
	"github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/ssh/config"
)

func registerStates(mgr *statemanager.Manager) {
	mgr.RegisterState(&dns.ShutdownState{})
	mgr.RegisterState(&systemops.ShutdownState{})
	mgr.RegisterState(&nftables.ShutdownState{})
	mgr.RegisterState(&iptables.ShutdownState{})
	mgr.RegisterState(&config.ShutdownState{})
}
