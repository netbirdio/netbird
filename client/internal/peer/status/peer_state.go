package status

import (
	"sync"
	"time"

	"golang.org/x/exp/maps"
)

// State contains the latest state of a peer
type State struct {
	Mux                        *sync.RWMutex
	IP                         string
	IPv6                       string
	PubKey                     string
	FQDN                       string
	ConnStatus                 ConnStatus
	ConnStatusUpdate           time.Time
	Relayed                    bool
	LocalIceCandidateType      string
	RemoteIceCandidateType     string
	LocalIceCandidateEndpoint  string
	RemoteIceCandidateEndpoint string
	RelayServerAddress         string
	LastWireguardHandshake     time.Time
	BytesTx                    int64
	BytesRx                    int64
	Latency                    time.Duration
	RosenpassEnabled           bool
	SSHHostKey                 []byte
	routes                     map[string]struct{}
}

// AddRoute add a single route to routes map
func (s *State) AddRoute(network string) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if s.routes == nil {
		s.routes = make(map[string]struct{})
	}
	s.routes[network] = struct{}{}
}

// SetRoutes set state routes
func (s *State) SetRoutes(routes map[string]struct{}) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.routes = routes
}

// DeleteRoute removes a route from the network amp
func (s *State) DeleteRoute(network string) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	delete(s.routes, network)
}

// GetRoutes return routes map
func (s *State) GetRoutes() map[string]struct{} {
	s.Mux.RLock()
	defer s.Mux.RUnlock()
	return maps.Clone(s.routes)
}
