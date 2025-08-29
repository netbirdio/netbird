package routemanager

import (
	"github.com/netbirdio/netbird/client/internal/routeselector"
)

type SelectorState routeselector.RouteSelector

func (s *SelectorState) Name() string {
	return "routeselector_state"
}

func (s *SelectorState) MarshalJSON() ([]byte, error) {
	return (*routeselector.RouteSelector)(s).MarshalJSON()
}

func (s *SelectorState) UnmarshalJSON(data []byte) error {
	return (*routeselector.RouteSelector)(s).UnmarshalJSON(data)
}
