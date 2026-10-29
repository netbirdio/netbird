package cache

import (
	"sync"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// DNSConfigCache is a thread-safe cache for DNS configuration components
type DNSConfigCache struct {
	NameServerGroups sync.Map
}

// GetNameServerGroup retrieves a cached name server group
func (c *DNSConfigCache) GetNameServerGroup(key string) (*proto.NameServerGroup, bool) {
	if c == nil {
		return nil, false
	}
	if value, ok := c.NameServerGroups.Load(key); ok {
		return value.(*proto.NameServerGroup), true
	}
	return nil, false
}

// SetNameServerGroup stores a name server group in the cache
func (c *DNSConfigCache) SetNameServerGroup(key string, value *proto.NameServerGroup) {
	if c == nil {
		return
	}
	c.NameServerGroups.Store(key, value)
}
