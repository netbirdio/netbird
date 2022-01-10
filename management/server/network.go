package server

import (
	"encoding/binary"
	"fmt"
	"net"
)

var (
	upperIPv4 = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 255, 255, 255, 255}
	upperIPv6 = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Network struct {
	Id  string
	Net net.IPNet
	Dns string
	// modificationId is an incrementing ID that increments by 1 when any change to the network happened (e.g. new peer has been added).
	// Used to synchronize state to the client apps.
	modificationId uint64
}

// IncrementModification increments modificationId reflecting that the network has been changed
func (n *Network) IncrementModification() {
	n.modificationId = n.modificationId + 1
}

// ModificationId returns the latest modificationId of the network
func (n *Network) ModificationId() uint64 {
	return n.modificationId
}

func (n *Network) Copy() *Network {
	return &Network{
		Id:             n.Id,
		Net:            n.Net,
		Dns:            n.Dns,
		modificationId: n.modificationId,
	}
}

// AllocatePeerIP pics an available IP from an net.IPNet.
// This method considers already taken IPs and reuses IPs if there are gaps in takenIps
// E.g. if ipNet=100.30.0.0/16 and takenIps=[100.30.0.1, 100.30.0.5] then the result would be 100.30.0.2
func AllocatePeerIP(ipNet net.IPNet, takenIps []net.IP) (net.IP, error) {
	takenIpMap := make(map[string]net.IP)
	takenIpMap[ipNet.IP.String()] = ipNet.IP
	for _, ip := range takenIps {
		takenIpMap[ip.String()] = ip
	}
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); ip = GetNextIP(ip) {
		if _, ok := takenIpMap[ip.String()]; !ok {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("failed allocating new IP for the ipNet %s and takenIps %s", ipNet.String(), takenIps)
}

// GetNextIP returns the next IP from the given IP address. If the given IP is
// the last IP of a v4 or v6 range, the same IP is returned.
// Credits to Cilium team.
// Copyright 2017-2020 Authors of Cilium
func GetNextIP(ip net.IP) net.IP {
	if ip.Equal(upperIPv4) || ip.Equal(upperIPv6) {
		return ip
	}

	nextIP := make(net.IP, len(ip))
	switch len(ip) {
	case net.IPv4len:
		ipU32 := binary.BigEndian.Uint32(ip)
		ipU32++
		binary.BigEndian.PutUint32(nextIP, ipU32)
		return nextIP
	case net.IPv6len:
		ipU64 := binary.BigEndian.Uint64(ip[net.IPv6len/2:])
		ipU64++
		binary.BigEndian.PutUint64(nextIP[net.IPv6len/2:], ipU64)
		if ipU64 == 0 {
			ipU64 = binary.BigEndian.Uint64(ip[:net.IPv6len/2])
			ipU64++
			binary.BigEndian.PutUint64(nextIP[:net.IPv6len/2], ipU64)
		} else {
			copy(nextIP[:net.IPv6len/2], ip[:net.IPv6len/2])
		}
		return nextIP
	default:
		return ip
	}
}
