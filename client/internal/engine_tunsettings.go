package internal

import "net/netip"

// DNSResolverAddress returns the active local NetBird DNS resolver endpoint.
func (e *Engine) DNSResolverAddress() (netip.AddrPort, bool) {
	e.syncMsgMux.Lock()
	dnsServer := e.dnsServer
	e.syncMsgMux.Unlock()

	if dnsServer == nil {
		return netip.AddrPort{}, false
	}
	return dnsServer.ResolverAddress()
}

func (e *Engine) TunSettings() ([]string, []string) {
	e.syncMsgMux.Lock()
	routeManager := e.routeManager
	dnsServer := e.dnsServer
	e.syncMsgMux.Unlock()

	var routes []string
	if routeManager != nil {
		routes = routeManager.CurrentRouteRange()
	}

	var searchDomains []string
	if dnsServer != nil {
		searchDomains = dnsServer.SearchDomains()
	}

	return routes, searchDomains
}
