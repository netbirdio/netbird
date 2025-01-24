package manager

import (
	"fmt"
	"net"
)

// ForwardRule todo figure out better place to this to avoid circular imports
type ForwardRule struct {
	Protocol          Protocol
	DestinationPort   Port
	TranslatedAddress net.IP
	TranslatedPort    Port
}

func (r ForwardRule) GetRuleID() string {
	return fmt.Sprintf("%s-%s-%s-%s",
		r.Protocol,
		r.DestinationPort,
		r.TranslatedAddress.String(),
		r.TranslatedPort)
}

func (r ForwardRule) String() string {
	return r.GetRuleID()
}
