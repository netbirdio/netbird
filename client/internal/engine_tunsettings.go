package internal

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
