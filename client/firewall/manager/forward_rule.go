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

func (r ForwardRule) GetRuleID() string {
	return fmt.Sprintf("%s;%s;%s;%s",
		r.Protocol,
		r.DestinationPort.String(),
		r.TranslatedAddress.String(),
		r.TranslatedPort.String())
}

func (r ForwardRule) String() string {
	return r.GetRuleID()
}
