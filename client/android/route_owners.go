package android

import (
	"github.com/netbirdio/netbird/client/internal/peer"
)

func routeOwners(states []peer.State) map[string]peer.State {
	owners := make(map[string]peer.State)
	for _, state := range states {
		for network := range state.GetRoutes() {
			if _, ok := owners[network]; !ok {
				owners[network] = state
			}
		}
	}
	return owners
}
