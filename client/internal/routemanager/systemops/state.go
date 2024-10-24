package systemops

import (
	"net/netip"
	"sync"

	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

type ShutdownState struct {
	Counter *ExclusionCounter `json:"counter,omitempty"`
	mu      sync.RWMutex
}

func (s *ShutdownState) Name() string {
	return "route_state"
}

func (s *ShutdownState) Cleanup() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Counter == nil {
		return nil
	}

	sysops := NewSysOps(nil, nil)
	sysops.refCounter = refcounter.New[netip.Prefix, struct{}, Nexthop](nil, sysops.removeFromRouteTable)
	sysops.refCounter.LoadData(s.Counter)

	return sysops.refCounter.Flush()
}
