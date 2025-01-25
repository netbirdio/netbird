package types

import (
	"fmt"
	"net/netip"
)

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
	return fmt.Sprintf("protocol: %s, destinationPort: %s, translatedAddress: %s, translatedPort: %s", r.Protocol, r.DestinationPort.String(), r.TranslatedAddress.String(), r.TranslatedPort.String())
}
