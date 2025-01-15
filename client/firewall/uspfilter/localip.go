package uspfilter

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
)

type localIPManager struct {
	mu sync.RWMutex

	// Use bitmap for IPv4 (32 bits * 2^16 = 256KB memory)
	ipv4Bitmap [1 << 16]uint32
}

func newLocalIPManager() *localIPManager {
	return &localIPManager{}
}

func (m *localIPManager) setBitmapBit(ip net.IP) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return
	}
	high := (uint16(ipv4[0]) << 8) | uint16(ipv4[1])
	low := (uint16(ipv4[2]) << 8) | uint16(ipv4[3])
	m.ipv4Bitmap[high] |= 1 << (low % 32)
}

func (m *localIPManager) checkBitmapBit(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	high := (uint16(ipv4[0]) << 8) | uint16(ipv4[1])
	low := (uint16(ipv4[2]) << 8) | uint16(ipv4[3])
	return (m.ipv4Bitmap[high] & (1 << (low % 32))) != 0
}

func (m *localIPManager) processIP(ip net.IP, newIPv4Bitmap *[1 << 16]uint32, ipv4Set map[string]struct{}, ipv4Addresses *[]string) error {
	if ipv4 := ip.To4(); ipv4 != nil {
		high := (uint16(ipv4[0]) << 8) | uint16(ipv4[1])
		low := (uint16(ipv4[2]) << 8) | uint16(ipv4[3])
		if int(high) >= len(*newIPv4Bitmap) {
			return fmt.Errorf("invalid IPv4 address: %s", ip)
		}
		ipStr := ip.String()
		if _, exists := ipv4Set[ipStr]; !exists {
			ipv4Set[ipStr] = struct{}{}
			*ipv4Addresses = append(*ipv4Addresses, ipStr)
			newIPv4Bitmap[high] |= 1 << (low % 32)
		}
	}
	return nil
}

func (m *localIPManager) processInterface(iface net.Interface, newIPv4Bitmap *[1 << 16]uint32, ipv4Set map[string]struct{}, ipv4Addresses *[]string) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Debugf("get addresses for interface %s failed: %v", iface.Name, err)
		return
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		if err := m.processIP(ip, newIPv4Bitmap, ipv4Set, ipv4Addresses); err != nil {
			log.Debugf("process IP failed: %v", err)
		}
	}
}

func (m *localIPManager) UpdateLocalIPs(iface common.IFaceMapper) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	var newIPv4Bitmap [1 << 16]uint32
	ipv4Set := make(map[string]struct{})
	var ipv4Addresses []string

	if iface != nil {
		if err := m.processIP(iface.Address().IP, &newIPv4Bitmap, ipv4Set, &ipv4Addresses); err != nil {
			return err
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Warnf("failed to get interfaces: %v", err)
	} else {
		for _, intf := range interfaces {
			m.processInterface(intf, &newIPv4Bitmap, ipv4Set, &ipv4Addresses)
		}
	}

	m.mu.Lock()
	m.ipv4Bitmap = newIPv4Bitmap
	m.mu.Unlock()

	log.Debugf("Local IPv4 addresses: %v", ipv4Addresses)
	return nil
}

func (m *localIPManager) IsLocalIP(ip net.IP) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if ipv4 := ip.To4(); ipv4 != nil {
		return m.checkBitmapBit(ipv4)
	}

	return false
}
