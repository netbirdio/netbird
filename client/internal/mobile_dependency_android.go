package internal

import (
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
)

func newMobileDependency(tunAdapter iface.TunAdapter, ifaceDiscover stdnet.ExternalIFaceDiscover, mgmClient *mgm.GrpcClient) (MobileDependency, error) {
	md := MobileDependency{
		TunAdapter:    tunAdapter,
		IFaceDiscover: ifaceDiscover,
	}
	err := md.readMap(mgmClient)
	return md, err
}

func (d *MobileDependency) readMap(mgmClient *mgm.GrpcClient) error {
	routes, err := mgmClient.GetRoutes()
	if err != nil {
		return err
	}

	d.Routes = make([]string, len(routes))
	for i, r := range routes {
		d.Routes[i] = r.GetNetwork()
	}
	return nil
}
