package manager

import (
	"net/netip"
)

type Manager interface {
	LoadWgProxy() error
	AddPeer(channelID, dstID uint16, dstAddr netip.AddrPort) error
}
