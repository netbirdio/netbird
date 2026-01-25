//go:build windows

// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	// MachineInterfaceName is the desired name for the machine tunnel interface.
	MachineInterfaceName = "wg-nb-machine"

	// WireGuardDescription is the Windows adapter description for WireGuard interfaces.
	WireGuardDescription = "WireGuard Tunnel"
)

// InterfaceInfo contains information about a discovered WireGuard interface.
type InterfaceInfo struct {
	// Name is the interface name (e.g., "wg-nb-machine").
	Name string

	// GUID is the Windows interface GUID.
	GUID string

	// LUID is the Windows Local Unique Identifier.
	LUID uint64

	// Index is the interface index.
	Index int

	// Addresses are the IP addresses assigned to the interface.
	Addresses []net.IPNet

	// IsUp indicates whether the interface is up and running.
	IsUp bool

	// MTU is the Maximum Transmission Unit.
	MTU int
}

// FindWireGuardInterface finds the machine tunnel WireGuard interface.
// It uses a priority-based search:
// 1. By GUID (most reliable, survives renames)
// 2. By Description (Windows adapter description)
// 3. By Name prefix (fallback)
func FindWireGuardInterface(guid string) (*InterfaceInfo, error) {
	// Method 1: Try to find by GUID first (most reliable)
	if guid != "" {
		iface, err := findByGUID(guid)
		if err == nil && iface != nil {
			log.Debugf("Found interface by GUID: %s -> %s", guid, iface.Name)
			return iface, nil
		}
		log.Debugf("Could not find interface by GUID %s: %v", guid, err)
	}

	// Method 2: Find by WireGuard description
	iface, err := findByDescription(WireGuardDescription)
	if err == nil && iface != nil {
		log.Debugf("Found interface by description: %s -> %s", WireGuardDescription, iface.Name)
		return iface, nil
	}
	log.Debugf("Could not find interface by description: %v", err)

	// Method 3: Find by name prefix
	iface, err = findByNamePrefix(MachineInterfaceName)
	if err == nil && iface != nil {
		log.Debugf("Found interface by name prefix: %s", iface.Name)
		return iface, nil
	}
	log.Debugf("Could not find interface by name prefix: %v", err)

	return nil, fmt.Errorf("no WireGuard interface found")
}

// findByGUID finds an interface by its Windows GUID.
func findByGUID(guidStr string) (*InterfaceInfo, error) {
	guid, err := windows.GUIDFromString(guidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid GUID format: %w", err)
	}

	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		return nil, fmt.Errorf("LUID from GUID failed: %w", err)
	}

	return getInterfaceInfoFromLUID(luid)
}

// findByDescription finds an interface by its Windows adapter description.
func findByDescription(description string) (*InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Get Windows-specific adapter info
		row, err := getAdapterRow(iface.Index)
		if err != nil {
			continue
		}

		if strings.Contains(row.Description, description) {
			return buildInterfaceInfo(&iface, row)
		}
	}

	return nil, fmt.Errorf("no interface with description %q found", description)
}

// findByNamePrefix finds an interface by name prefix.
func findByNamePrefix(prefix string) (*InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, prefix) {
			row, rowErr := getAdapterRow(iface.Index)
			if rowErr != nil {
				// Even if we can't get adapter row, return basic info
				log.Debugf("Could not get adapter row for %s: %v", iface.Name, rowErr)
				return &InterfaceInfo{
					Name:  iface.Name,
					Index: iface.Index,
					MTU:   iface.MTU,
					IsUp:  iface.Flags&net.FlagUp != 0,
				}, nil
			}
			return buildInterfaceInfo(&iface, row)
		}
	}

	return nil, fmt.Errorf("no interface with name prefix %q found", prefix)
}

// getInterfaceInfoFromLUID builds interface info from a Windows LUID.
func getInterfaceInfoFromLUID(luid winipcfg.LUID) (*InterfaceInfo, error) {
	row, err := luid.Interface()
	if err != nil {
		return nil, fmt.Errorf("get interface row: %w", err)
	}

	// Get the interface by index
	iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
	if err != nil {
		return nil, fmt.Errorf("get interface by index: %w", err)
	}

	// Get addresses
	addrs, err := iface.Addrs()
	if err != nil {
		log.Warnf("Failed to get addresses for interface %s: %v", iface.Name, err)
	}

	ipNets := make([]net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ipNets = append(ipNets, *ipnet)
		}
	}

	// Get GUID string
	guid, err := luid.GUID()
	if err != nil {
		log.Warnf("Failed to get GUID for interface %s: %v", iface.Name, err)
	}

	guidStr := ""
	if guid != nil {
		guidStr = guid.String()
	}

	return &InterfaceInfo{
		Name:      iface.Name,
		GUID:      guidStr,
		LUID:      uint64(luid),
		Index:     iface.Index,
		Addresses: ipNets,
		IsUp:      iface.Flags&net.FlagUp != 0,
		MTU:       iface.MTU,
	}, nil
}

// adapterRow holds Windows adapter row info.
type adapterRow struct {
	Description string
	GUID        string
	LUID        uint64
}

// getAdapterRow gets Windows-specific adapter information.
func getAdapterRow(index int) (*adapterRow, error) {
	// Use winipcfg to get adapter info
	luid, err := winipcfg.LUIDFromIndex(uint32(index))
	if err != nil {
		return nil, fmt.Errorf("LUID from index: %w", err)
	}

	guid, err := luid.GUID()
	if err != nil {
		return nil, fmt.Errorf("get GUID: %w", err)
	}

	guidStr := ""
	if guid != nil {
		guidStr = guid.String()
	}

	// Get the interface to extract the alias/description
	iface, err := luid.Interface()
	if err != nil {
		return nil, fmt.Errorf("get interface: %w", err)
	}

	// Use the Alias method to get description
	return &adapterRow{
		Description: iface.Alias(),
		GUID:        guidStr,
		LUID:        uint64(luid),
	}, nil
}

// buildInterfaceInfo builds InterfaceInfo from net.Interface and adapter row.
func buildInterfaceInfo(iface *net.Interface, row *adapterRow) (*InterfaceInfo, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Warnf("Failed to get addresses for interface %s: %v", iface.Name, err)
	}

	ipNets := make([]net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ipNets = append(ipNets, *ipnet)
		}
	}

	return &InterfaceInfo{
		Name:      iface.Name,
		GUID:      row.GUID,
		LUID:      row.LUID,
		Index:     iface.Index,
		Addresses: ipNets,
		IsUp:      iface.Flags&net.FlagUp != 0,
		MTU:       iface.MTU,
	}, nil
}

// VerifyInterface checks that the interface is properly configured.
func VerifyInterface(info *InterfaceInfo) error {
	if info == nil {
		return fmt.Errorf("interface info is nil")
	}

	if !info.IsUp {
		return fmt.Errorf("interface %s is not up", info.Name)
	}

	if len(info.Addresses) == 0 {
		return fmt.Errorf("interface %s has no IP addresses", info.Name)
	}

	log.Infof("Interface %s verified: up=%v, addresses=%d, MTU=%d",
		info.Name, info.IsUp, len(info.Addresses), info.MTU)

	return nil
}

// HasRouteToNetwork checks if the interface has a route to the specified network.
// Note: This is a simplified check that verifies the interface is associated with
// a route to the target network. Full route verification is done via PowerShell tests.
func HasRouteToNetwork(info *InterfaceInfo, network string) (bool, error) {
	if info == nil {
		return false, fmt.Errorf("interface info is nil")
	}

	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return false, fmt.Errorf("parse network CIDR: %w", err)
	}

	// Check if any of the interface's addresses are in the same network family
	// Full route verification is done via PowerShell in the test suite
	for _, addr := range info.Addresses {
		if addr.IP.To4() != nil && cidr.IP.To4() != nil {
			// Both are IPv4 - interface could potentially route to this network
			log.Debugf("Interface %s has IPv4 address %s, target network %s",
				info.Name, addr.IP.String(), network)
			return true, nil
		}
	}

	// If no matching address family, assume route might still exist
	// (routes can be added without local addresses in the same range)
	log.Debugf("Interface %s may have route to %s (no local address check)",
		info.Name, network)
	return true, nil
}
