package internal

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/firewall/types"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func convertToFirewallProtocol(protocol mgmProto.RuleProtocol) (types.Protocol, error) {
	switch protocol {
	case mgmProto.RuleProtocol_TCP:
		return types.ProtocolTCP, nil
	case mgmProto.RuleProtocol_UDP:
		return types.ProtocolUDP, nil
	case mgmProto.RuleProtocol_ICMP:
		return types.ProtocolICMP, nil
	case mgmProto.RuleProtocol_ALL:
		return types.ProtocolALL, nil
	default:
		return types.ProtocolALL, fmt.Errorf("invalid protocol type: %s", protocol.String())
	}
}

// convertPortInfo todo: write validation for portInfo
func convertPortInfo(portInfo *mgmProto.PortInfo) *types.Port {
	if portInfo == nil {
		return nil
	}

	if portInfo.GetPort() != 0 {
		return &types.Port{
			Values: []int{int(portInfo.GetPort())},
		}
	}

	if portInfo.GetRange() != nil {
		return &types.Port{
			IsRange: true,
			Values:  []int{int(portInfo.GetRange().Start), int(portInfo.GetRange().End)},
		}
	}

	return nil
}

func convertToIP(rawIP []byte) (netip.Addr, error) {
	if rawIP == nil {
		return netip.Addr{}, errors.New("input bytes cannot be nil")
	}

	if len(rawIP) != net.IPv4len && len(rawIP) != net.IPv6len {
		return netip.Addr{}, fmt.Errorf("invalid IP length: %d", len(rawIP))
	}

	if len(rawIP) == net.IPv4len {
		return netip.AddrFrom4([4]byte(rawIP)), nil
	}

	return netip.AddrFrom16([16]byte(rawIP)), nil
}
