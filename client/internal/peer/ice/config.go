package ice

import (
	"sync/atomic"

	"github.com/pion/ice/v3"
)

type Config struct {
	// StunTurn is a list of STUN and TURN URLs
	StunTurn *atomic.Value // []*stun.URI

	// InterfaceBlackList is a list of machine interfaces that should be filtered out by ICE Candidate gathering
	// (e.g. if eth0 is in the list, host candidate of this interface won't be used)
	InterfaceBlackList   []string
	DisableIPv6Discovery bool

	UDPMux      ice.UDPMux
	UDPMuxSrflx ice.UniversalUDPMux

	NATExternalIPs []string
}
