package wgbackend

import (
	"github.com/netbirdio/wireguard-go/tun"
	"github.com/netbirdio/wireguard-go/tun/netstack"
)

type (
	// TUN is the packet device the WireGuard device reads from and writes to.
	TUN = tun.Device
	// TUNEvent is a status change reported by a TUN.
	TUNEvent = tun.Event
	// NetstackNet is the userspace network stack a netstack TUN is attached to.
	NetstackNet = netstack.Net
)

const TUNEventDown = tun.EventDown

var CreateNetTUN = netstack.CreateNetTUN
