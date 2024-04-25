package routemanager

import "github.com/netbirdio/netbird/route"

type serverRouter interface {
	updateRoutes(map[route.ID]*route.Route) error
	removeFromServerNetwork(*route.Route) error
	cleanUp()
}
