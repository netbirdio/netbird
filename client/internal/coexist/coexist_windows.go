//go:build windows

package coexist

import (
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// OtherOverlayRoutes returns the destination prefixes of the routes on NetBird
// adapters other than ownIface.
func OtherOverlayRoutes(ownIface string) ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	names := make(map[uint32]string, len(ifaces))
	for _, iface := range ifaces {
		names[uint32(iface.Index)] = iface.Name
	}

	table, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("read route table: %w", err)
	}
	var out []netip.Prefix
	for i := range table {
		name := names[table[i].InterfaceIndex]
		if name == ownIface || !IsOverlayInterface(name) {
			continue
		}
		if p := table[i].DestinationPrefix.Prefix(); p.IsValid() {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// OtherPrimary names another primary installation when inst is a primary named
// installation: the default installation, whose service exists, or a record
// with Role=primary. Two primaries compete for exit nodes and system DNS.
func OtherPrimary(inst instance.Instance) (string, bool) {
	if inst.IsDefault() || inst.IsSecondary() {
		return "", false
	}
	if serviceExists(instance.Default().ServiceName()) {
		return "the default installation", true
	}
	recs, err := instance.ListRecords()
	if err != nil {
		log.Debugf("list installation records: %v", err)
		return "", false
	}
	for _, rec := range recs {
		if rec.Name == inst.Name() {
			continue
		}
		if role, err := instance.ParseRole(rec.Role); err == nil && role == instance.RolePrimary {
			return "the named installation " + string(rec.Name), true
		}
	}
	return "", false
}

func serviceExists(name string) bool {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	_ = windows.CloseServiceHandle(h)
	return true
}
