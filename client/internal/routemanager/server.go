package routemanager

import "github.com/netbirdio/netbird/route"

type serverRouter interface {
	updateRoutes(map[string]*route.Route) error
	removeFromServerNetwork(*route.Route) error
	cleanUp()
}
