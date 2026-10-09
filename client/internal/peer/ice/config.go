package ice

import (
	"github.com/pion/ice/v4"

	"github.com/netbirdio/netbird/client/internal/stdnet"
)

type Config struct {
	// StunTurn is a list of STUN and TURN URLs
	StunTurn *StunTurn // []*stun.URI

	// InterfaceBlackList is a list of machine interfaces that should be filtered out by ICE Candidate gathering
	// (e.g. if eth0 is in the list, host candidate of this interface won't be used)
	InterfaceBlackList   []string
	DisableIPv6Discovery bool

	UDPMux      ice.UDPMux
	UDPMuxSrflx ice.UniversalUDPMux

	NATExternalIPs []string

	// WGDetector is shared by every agent so that the WireGuard check the interface
	// filter performs is not repeated for each of them.
	WGDetector *stdnet.WGDetector
}
