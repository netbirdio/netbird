package android

import (
	"fmt"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/dns"
)

// DNSList is a wrapper of []netip.AddrPort with default DNS port
type DNSList struct {
	items []netip.AddrPort
}

// Add new DNS address to the collection, returns error if invalid
func (array *DNSList) Add(s string) error {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid DNS address: %s", s)
	}
	addrPort := netip.AddrPortFrom(addr.Unmap(), dns.DefaultPort)
	array.items = append(array.items, addrPort)
	return nil
}

// Get return an element of the collection as string
func (array *DNSList) Get(i int) (string, error) {
	if i >= len(array.items) || i < 0 {
		return "", fmt.Errorf("out of range")
	}
	return array.items[i].Addr().String(), nil
}

// Size return with the size of the collection
func (array *DNSList) Size() int {
	return len(array.items)
}
