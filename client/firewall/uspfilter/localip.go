package uspfilter

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
)

type localIPManager struct {
	mu sync.RWMutex

	// fixed-size high array for upper byte of a IPv4 address
	ipv4Bitmap [256]*ipv4LowBitmap
}

// ipv4LowBitmap is a map for the low 16 bits of a IPv4 address
type ipv4LowBitmap struct {
	bitmap [8192]uint32
}

func newLocalIPManager() *localIPManager {
	return &localIPManager{}
}

func (m *localIPManager) setBitmapBit(ip net.IP) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return
	}
	high := uint16(ipv4[0])
	low := (uint16(ipv4[1]) << 8) | (uint16(ipv4[2]) << 4) | uint16(ipv4[3])

	index := low / 32
	bit := low % 32

	if m.ipv4Bitmap[high] == nil {
		m.ipv4Bitmap[high] = &ipv4LowBitmap{}
	}

	m.ipv4Bitmap[high].bitmap[index] |= 1 << bit
}

func (m *localIPManager) setBitInBitmap(ip netip.Addr, bitmap *[256]*ipv4LowBitmap, ipv4Set map[netip.Addr]struct{}, ipv4Addresses *[]netip.Addr) {
	if !ip.Is4() {
		return
	}
	ipv4 := ip.AsSlice()

	high := uint16(ipv4[0])
	low := (uint16(ipv4[1]) << 8) | (uint16(ipv4[2]) << 4) | uint16(ipv4[3])

	if bitmap[high] == nil {
		bitmap[high] = &ipv4LowBitmap{}
	}

	index := low / 32
	bit := low % 32
	bitmap[high].bitmap[index] |= 1 << bit

	if _, exists := ipv4Set[ip]; !exists {
		ipv4Set[ip] = struct{}{}
		*ipv4Addresses = append(*ipv4Addresses, ip)
	}
}

func (m *localIPManager) checkBitmapBit(ip []byte) bool {
	high := uint16(ip[0])
	low := (uint16(ip[1]) << 8) | (uint16(ip[2]) << 4) | uint16(ip[3])

	if m.ipv4Bitmap[high] == nil {
		return false
	}

	index := low / 32
	bit := low % 32
	return (m.ipv4Bitmap[high].bitmap[index] & (1 << bit)) != 0
}

func (m *localIPManager) processIP(ip netip.Addr, bitmap *[256]*ipv4LowBitmap, ipv4Set map[netip.Addr]struct{}, ipv4Addresses *[]netip.Addr) error {
	m.setBitInBitmap(ip, bitmap, ipv4Set, ipv4Addresses)
	return nil
}

func (m *localIPManager) processInterface(iface net.Interface, bitmap *[256]*ipv4LowBitmap, ipv4Set map[netip.Addr]struct{}, ipv4Addresses *[]netip.Addr) {
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

		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			log.Warnf("invalid IP address %s in interface %s", ip.String(), iface.Name)
			continue
		}

		if err := m.processIP(addr.Unmap(), bitmap, ipv4Set, ipv4Addresses); err != nil {
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

	var newIPv4Bitmap [256]*ipv4LowBitmap
	ipv4Set := make(map[netip.Addr]struct{})
	var ipv4Addresses []netip.Addr

	// 127.0.0.0/8
	newIPv4Bitmap[127] = &ipv4LowBitmap{}
	for i := 0; i < 8192; i++ {
		// #nosec G602 -- bitmap is defined as [8192]uint32, loop range is correct
		newIPv4Bitmap[127].bitmap[i] = 0xFFFFFFFF
	}

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

func (m *localIPManager) IsLocalIP(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.checkBitmapBit(ip.AsSlice())
}
