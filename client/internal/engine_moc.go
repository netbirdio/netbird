package internal

import (
	"net/netip"

	log "github.com/sirupsen/logrus"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/ingressgw"
)

func (e *Engine) mocForwardRules() {
	if e.ingressGatewayMgr == nil {
		e.ingressGatewayMgr = ingressgw.NewManager(e.firewall)
	}
	err := e.ingressGatewayMgr.Update(
		[]firewallManager.ForwardRule{
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: false, Values: []int{10000}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: false, Values: []int{20000}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10100, 10199}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20100, 20199}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10200, 10299}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20200, 20299}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10300, 10399}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20300, 20399}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10100, 10199}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20100, 20199}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10400, 10499}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20400, 20499}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10500, 10599}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20500, 20599}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10600, 10699}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20600, 20699}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10700, 10799}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20700, 20799}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10800, 10899}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20800, 20899}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{10900, 10999}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{20900, 20999}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11000, 11099}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21000, 21099}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11100, 11199}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21100, 21199}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11200, 11299}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21200, 21299}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11300, 11399}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21300, 21399}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11400, 11499}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21400, 21499}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11500, 11599}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21500, 21599}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11600, 11699}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21600, 21699}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11700, 11799}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21700, 21799}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11800, 11899}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21800, 21899}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{11900, 11999}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{21900, 21999}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12000, 12099}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22000, 22099}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12100, 12199}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22100, 22199}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12200, 12299}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22200, 22299}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12300, 12399}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22300, 22399}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12400, 12499}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22400, 22499}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12500, 12599}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22500, 22599}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12600, 12699}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22600, 22699}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12700, 12799}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22700, 22799}},
			},
			{
				Protocol:          "tcp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12800, 12899}},
				TranslatedAddress: netip.MustParseAddr("100.64.31.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22800, 22899}},
			},
			{
				Protocol:          "udp",
				DestinationPort:   firewallManager.Port{IsRange: true, Values: []int{12900, 12999}},
				TranslatedAddress: netip.MustParseAddr("100.64.10.206"),
				TranslatedPort:    firewallManager.Port{IsRange: true, Values: []int{22900, 22999}},
			},
		},
	)

	if err != nil {
		log.Errorf("failed to update forwarding rules: %v", err)
	}
}
