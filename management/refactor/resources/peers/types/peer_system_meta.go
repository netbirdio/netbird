package types

import "net/netip"

// NetworkAddress is the IP address with network and MAC address of a network interface
type NetworkAddress struct {
	NetIP netip.Prefix `gorm:"serializer:json"`
	Mac   string
}

// Environment is a system environment information
type Environment struct {
	Cloud    string
	Platform string
}

// PeerSystemMeta is a metadata of a Peer machine system
type PeerSystemMeta struct { //nolint:revive
	Hostname           string
	GoOS               string
	Kernel             string
	Core               string
	Platform           string
	OS                 string
	OSVersion          string
	WtVersion          string
	UIVersion          string
	KernelVersion      string
	NetworkAddresses   []NetworkAddress `gorm:"serializer:json"`
	SystemSerialNumber string
	SystemProductName  string
	SystemManufacturer string
	Environment        Environment `gorm:"serializer:json"`
}

func (p PeerSystemMeta) isEqual(other PeerSystemMeta) bool {
	if len(p.NetworkAddresses) != len(other.NetworkAddresses) {
		return false
	}

	for _, addr := range p.NetworkAddresses {
		var found bool
		for _, oAddr := range other.NetworkAddresses {
			if addr.Mac == oAddr.Mac && addr.NetIP == oAddr.NetIP {
				found = true
				continue
			}
		}
		if !found {
			return false
		}
	}

	return p.Hostname == other.Hostname &&
		p.GoOS == other.GoOS &&
		p.Kernel == other.Kernel &&
		p.KernelVersion == other.KernelVersion &&
		p.Core == other.Core &&
		p.Platform == other.Platform &&
		p.OS == other.OS &&
		p.OSVersion == other.OSVersion &&
		p.WtVersion == other.WtVersion &&
		p.UIVersion == other.UIVersion &&
		p.SystemSerialNumber == other.SystemSerialNumber &&
		p.SystemProductName == other.SystemProductName &&
		p.SystemManufacturer == other.SystemManufacturer &&
		p.Environment.Cloud == other.Environment.Cloud &&
		p.Environment.Platform == other.Environment.Platform
}
