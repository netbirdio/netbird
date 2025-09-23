package net

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
)

const (
	// ControlPlaneMark is the fwmark value used to mark packets that should not be routed through the NetBird interface to
	// avoid routing loops.
	// This includes all control plane traffic (mgmt, signal, flows), relay, ICE/stun/turn and everything that is emitted by the wireguard socket.
	// It doesn't collide with the other marks, as the others are used for data plane traffic only.
	ControlPlaneMark = 0x1BD00

	// Data plane marks (0x1BD10 - 0x1BDFF)

	// DataPlaneMarkLower is the lowest value for the data plane range
	DataPlaneMarkLower = 0x1BD10
	// DataPlaneMarkUpper is the highest value for the data plane range
	DataPlaneMarkUpper = 0x1BDFF

	// DataPlaneMarkIn is the mark for inbound data plane traffic.
	DataPlaneMarkIn = 0x1BD10

	// DataPlaneMarkOut is the mark for outbound data plane traffic.
	DataPlaneMarkOut = 0x1BD11

	// PreroutingFwmarkRedirected is applied to packets that are were redirected (input -> forward, e.g. by Docker or Podman) for special handling.
	PreroutingFwmarkRedirected = 0x1BD20

	// PreroutingFwmarkMasquerade is applied to packets that arrive from the NetBird interface and should be masqueraded.
	PreroutingFwmarkMasquerade = 0x1BD21

	// PreroutingFwmarkMasqueradeReturn is applied to packets that will leave through the NetBird interface and should be masqueraded.
	PreroutingFwmarkMasqueradeReturn = 0x1BD22
)

// IsDataPlaneMark determines if a fwmark is in the data plane range (0x1BD10-0x1BDFF)
func IsDataPlaneMark(fwmark uint32) bool {
	return fwmark >= DataPlaneMarkLower && fwmark <= DataPlaneMarkUpper
}

func GetLastIPFromNetwork(network netip.Prefix, fromEnd int) (netip.Addr, error) {
	var endIP net.IP
	addr := network.Addr().AsSlice()
	mask := net.CIDRMask(network.Bits(), len(addr)*8)

	for i := 0; i < len(addr); i++ {
		endIP = append(endIP, addr[i]|^mask[i])
	}

	// convert to big.Int
	endInt := big.NewInt(0)
	endInt.SetBytes(endIP)

	// subtract fromEnd from the last ip
	fromEndBig := big.NewInt(int64(fromEnd))
	resultInt := big.NewInt(0)
	resultInt.Sub(endInt, fromEndBig)

	ip, ok := netip.AddrFromSlice(resultInt.Bytes())
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address from network %s", network)
	}

	return ip.Unmap(), nil
}
