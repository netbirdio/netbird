package nftables

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

var (
	// afIPv4 defines IPv4 header layout and nftables types.
	afIPv4 = addrFamily{
		protoOffset:   9,
		srcAddrOffset: 12,
		dstAddrOffset: 16,
		addrLen:       net.IPv4len,
		totalBits:     8 * net.IPv4len,
		setKeyType:    nftables.TypeIPAddr,
		tableFamily:   nftables.TableFamilyIPv4,
		icmpProto:     unix.IPPROTO_ICMP,
	}
	// afIPv6 defines IPv6 header layout and nftables types.
	afIPv6 = addrFamily{
		protoOffset:   6,
		srcAddrOffset: 8,
		dstAddrOffset: 24,
		addrLen:       net.IPv6len,
		totalBits:     8 * net.IPv6len,
		setKeyType:    nftables.TypeIP6Addr,
		tableFamily:   nftables.TableFamilyIPv6,
		icmpProto:     unix.IPPROTO_ICMPV6,
	}
)

// addrFamily holds protocol-specific constants for nftables expression building.
type addrFamily struct {
	// protoOffset is the IP header offset for the protocol/next-header field (9 for v4, 6 for v6)
	protoOffset uint32
	// srcAddrOffset is the IP header offset for the source address (12 for v4, 8 for v6)
	srcAddrOffset uint32
	// dstAddrOffset is the IP header offset for the destination address (16 for v4, 24 for v6)
	dstAddrOffset uint32
	// addrLen is the byte length of addresses (4 for v4, 16 for v6)
	addrLen uint32
	// totalBits is the address size in bits (32 for v4, 128 for v6)
	totalBits int
	// setKeyType is the nftables set data type for addresses
	setKeyType nftables.SetDatatype
	// tableFamily is the nftables table family
	tableFamily nftables.TableFamily
	// icmpProto is the ICMP protocol number for this family (1 for v4, 58 for v6)
	icmpProto uint8
}

// familyForAddr returns the address family for the given IP.
func familyForAddr(is4 bool) addrFamily {
	if is4 {
		return afIPv4
	}
	return afIPv6
}

// protoNum converts a firewall protocol to the IP protocol number,
// using the correct ICMP variant for the address family.
func (af addrFamily) protoNum(protocol firewall.Protocol) (uint8, error) {
	switch protocol {
	case firewall.ProtocolTCP:
		return unix.IPPROTO_TCP, nil
	case firewall.ProtocolUDP:
		return unix.IPPROTO_UDP, nil
	case firewall.ProtocolICMP:
		return af.icmpProto, nil
	case firewall.ProtocolALL:
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}
