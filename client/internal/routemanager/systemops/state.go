package systemops

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

type ShutdownState ExclusionCounter

func (s *ShutdownState) Name() string {
	return "route_state"
}

func (s *ShutdownState) Cleanup() error {
	sysOps := New(nil, nil)
	sysOps.refCounter = refcounter.New[netip.Prefix, struct{}, Nexthop](nil, sysOps.removeFromRouteTable)
	sysOps.refCounter.LoadData((*ExclusionCounter)(s))

	return sysOps.refCounter.Flush()
}

func (s *ShutdownState) MarshalJSON() ([]byte, error) {
	return (*ExclusionCounter)(s).MarshalJSON()
}

func (s *ShutdownState) UnmarshalJSON(data []byte) error {
	return (*ExclusionCounter)(s).UnmarshalJSON(data)
}
