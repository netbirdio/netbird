package manager

import (
	"fmt"
	"net/netip"
)

// ForwardRule todo figure out better place to this to avoid circular imports
type ForwardRule struct {
	Protocol          Protocol
	DestinationPort   Port
	TranslatedAddress netip.Addr
	TranslatedPort    Port
}

func (r ForwardRule) ID() string {
	id := fmt.Sprintf("%s;%s;%s;%s",
		r.Protocol,
		r.DestinationPort.String(),
		r.TranslatedAddress.String(),
		r.TranslatedPort.String())
	return id
}

func (r ForwardRule) String() string {
	return fmt.Sprintf("protocol: %s, destinationPort: %s, translatedAddress: %s, translatedPort: %s", r.Protocol, r.DestinationPort.String(), r.TranslatedAddress.String(), r.TranslatedPort.String())
}
