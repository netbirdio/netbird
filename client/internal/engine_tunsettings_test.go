package internal

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/dns"
)

func TestDNSResolverAddress(t *testing.T) {
	want := netip.MustParseAddrPort("127.0.0.153:5053")
	engine := &Engine{
		syncMsgMux: &sync.Mutex{},
		dnsServer: &dns.MockServer{
			ResolverAddressFunc: func() (netip.AddrPort, bool) {
				return want, true
			},
		},
	}

	got, ok := engine.DNSResolverAddress()
	assert.True(t, ok, "running DNS server should expose its resolver endpoint")
	assert.Equal(t, want, got, "engine should return the DNS server endpoint")

	emptyEngine := &Engine{syncMsgMux: &sync.Mutex{}}
	_, ok = emptyEngine.DNSResolverAddress()
	assert.False(t, ok, "stopped engine should not expose a resolver endpoint")
}
