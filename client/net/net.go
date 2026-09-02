package net

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
)

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
