package internal

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
)

type MobileDependency struct {
	TunAdapter    iface.TunAdapter
	IFaceDiscover stdnet.IFaceDiscover
	Routes        []string
}
