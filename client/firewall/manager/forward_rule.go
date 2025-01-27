package manager

import (
	"fmt"
	"net/netip"
)

type ForwardRuleID string

// ForwardRule todo figure out better place to this to avoid circular imports
type ForwardRule struct {
	Protocol          Protocol
	DestinationPort   Port
	TranslatedAddress netip.Addr
	TranslatedPort    Port
}

func (r ForwardRule) ID() ForwardRuleID {
	id := fmt.Sprintf("%s;%s;%s;%s",
		r.Protocol,
		r.DestinationPort.String(),
		r.TranslatedAddress.String(),
		r.TranslatedPort.String())
	return ForwardRuleID(id)
}

func (r ForwardRule) String() string {
	return fmt.Sprintf("protocol: %s, destinationPort: %s, translatedAddress: %s, translatedPort: %s", r.Protocol, r.DestinationPort.String(), r.TranslatedAddress.String(), r.TranslatedPort.String())
}
