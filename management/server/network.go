package server

import (
	"encoding/binary"
	"net"
)

var (
	upperIPv4 = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 255, 255, 255, 255}
	upperIPv6 = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Network struct {
	Id     string
	Net    net.IPNet
	Dns    string
	LastIP net.IP
}

// GetNextIP returns the next IP from the given IP address. If the given IP is
// the last IP of a v4 or v6 range, the same IP is returned.
// Credits to Cilium team.
// Copyright 2017-2020 Authors of Cilium
func (n *Network) GetNextIP() net.IP {
	lastIP := n.LastIP
	if lastIP.Equal(upperIPv4) || lastIP.Equal(upperIPv6) {
		return lastIP
	}

	nextIP := make(net.IP, len(lastIP))
	switch len(lastIP) {
	case net.IPv4len:
		ipU32 := binary.BigEndian.Uint32(lastIP)
		ipU32++
		binary.BigEndian.PutUint32(nextIP, ipU32)
		return nextIP
	case net.IPv6len:
		ipU64 := binary.BigEndian.Uint64(lastIP[net.IPv6len/2:])
		ipU64++
		binary.BigEndian.PutUint64(nextIP[net.IPv6len/2:], ipU64)
		if ipU64 == 0 {
			ipU64 = binary.BigEndian.Uint64(lastIP[:net.IPv6len/2])
			ipU64++
			binary.BigEndian.PutUint64(nextIP[:net.IPv6len/2], ipU64)
		} else {
			copy(nextIP[:net.IPv6len/2], lastIP[:net.IPv6len/2])
		}
		return nextIP
	default:
		return lastIP
	}
}
