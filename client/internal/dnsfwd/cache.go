package dnsfwd

import (
	"net/netip"
	"sync"

	"github.com/miekg/dns"
)

type cache struct {
	mu      sync.RWMutex
	records map[string]*cacheEntry
}

type cacheEntry struct {
	ip4Addrs []netip.Addr
	ip6Addrs []netip.Addr
}

func newCache() *cache {
	return &cache{
		records: make(map[string]*cacheEntry),
	}
}

func (c *cache) get(domain string, reqType uint16) ([]netip.Addr, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, exists := c.records[domain]
	if !exists {
		return nil, false
	}

	switch reqType {
	case dns.TypeA:
		return cloneAddrs(entry.ip4Addrs), len(entry.ip4Addrs) > 0
	case dns.TypeAAAA:
		return cloneAddrs(entry.ip6Addrs), len(entry.ip6Addrs) > 0
	default:
		return nil, false
	}

}

func (c *cache) set(domain string, reqType uint16, addrs []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, exists := c.records[domain]
	if !exists {
		entry = &cacheEntry{}
		c.records[domain] = entry
	}

	switch reqType {
	case dns.TypeA:
		entry.ip4Addrs = cloneAddrs(addrs)
	case dns.TypeAAAA:
		entry.ip6Addrs = cloneAddrs(addrs)
	}
}

func cloneAddrs(in []netip.Addr) []netip.Addr {
	if in == nil {
		return nil
	}
	out := make([]netip.Addr, len(in))
	copy(out, in)
	return out
}
