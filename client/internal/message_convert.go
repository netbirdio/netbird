package internal

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func convertPortInfo(portInfo *mgmProto.PortInfo) (*firewallManager.Port, error) {
	if portInfo == nil {
		return nil, errors.New("portInfo cannot be nil")
	}

	if portInfo.GetPort() != 0 {
		return firewallManager.NewPort(int(portInfo.GetPort()))
	}

	if portInfo.GetRange() != nil {
		return firewallManager.NewPort(int(portInfo.GetRange().Start), int(portInfo.GetRange().End))
	}

	return nil, fmt.Errorf("invalid portInfo: %v", portInfo)
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
