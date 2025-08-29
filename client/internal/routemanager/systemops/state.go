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
	sysops := NewSysOps(nil, nil)
	sysops.refCounter = refcounter.New[netip.Prefix, struct{}, Nexthop](nil, sysops.removeFromRouteTable)
	sysops.refCounter.LoadData((*ExclusionCounter)(s))

	return sysops.refCounter.Flush()
}

func (s *ShutdownState) MarshalJSON() ([]byte, error) {
	return (*ExclusionCounter)(s).MarshalJSON()
}

func (s *ShutdownState) UnmarshalJSON(data []byte) error {
	return (*ExclusionCounter)(s).UnmarshalJSON(data)
}
