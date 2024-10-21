package systemops

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

type RouteEntry struct {
	Prefix  netip.Prefix `json:"prefix"`
	Nexthop Nexthop      `json:"nexthop"`
}

type ShutdownState struct {
	Routes map[netip.Prefix]RouteEntry `json:"routes,omitempty"`
	mu     sync.RWMutex
}

func NewShutdownState() *ShutdownState {
	return &ShutdownState{
		Routes: make(map[netip.Prefix]RouteEntry),
	}
}

func (s *ShutdownState) Name() string {
	return "route_state"
}

func (s *ShutdownState) Cleanup() error {
	sysops := NewSysOps(nil, nil)
	var merr *multierror.Error

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.Routes {
		if err := sysops.removeFromRouteTable(route.Prefix, route.Nexthop); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove route %s: %w", route.Prefix, err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (s *ShutdownState) UpdateRoute(prefix netip.Prefix, nexthop Nexthop) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Routes[prefix] = RouteEntry{
		Prefix:  prefix,
		Nexthop: nexthop,
	}
}

func (s *ShutdownState) RemoveRoute(prefix netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.Routes, prefix)
}

// MarshalJSON ensures that empty routes are marshaled as null
func (s *ShutdownState) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.Routes) == 0 {
		return json.Marshal(nil)
	}

	return json.Marshal(s.Routes)
}

func (s *ShutdownState) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &s.Routes)
}
