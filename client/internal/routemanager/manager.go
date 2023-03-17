package routemanager

import "github.com/netbirdio/netbird/route"

// Manager is a route manager interface
type Manager interface {
	UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error
	Stop()
}
