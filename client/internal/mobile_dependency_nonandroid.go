//go:build !android

package internal

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
)

func newMobileDependency(tunAdapter iface.TunAdapter, ifaceDiscover stdnet.IFaceDiscover, mgmClient *mgm.GrpcClient) (MobileDependency, error) {
	return MobileDependency{}, nil
}
