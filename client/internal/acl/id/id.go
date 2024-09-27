package id

import (
	"fmt"
	"net/netip"

	"github.com/netbirdio/netbird/client/firewall/manager"
)

type RuleID string

func (r RuleID) GetRuleID() string {
	return string(r)
}

func GenerateRouteRuleKey(sources []netip.Prefix, destination netip.Prefix, proto manager.Protocol, sPort *manager.Port, dPort *manager.Port, direction manager.RuleDirection, action manager.Action) RuleID {
	return RuleID(fmt.Sprintf("%s-%s-%s-%s-%s-%d-%d", sources, destination, proto, sPort, dPort, direction, action))
}
