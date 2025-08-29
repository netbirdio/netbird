package peer

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// FQDNOld is the original implementation for benchmarking purposes
func (p *Peer) FQDNOld(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", p.DNSLabel, dnsDomain)
}

func BenchmarkFQDN(b *testing.B) {
	p := &Peer{DNSLabel: "test-peer"}
	dnsDomain := "example.com"

	b.Run("Old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.FQDNOld(dnsDomain)
		}
	})

	b.Run("New", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.FQDN(dnsDomain)
		}
	})
}

func TestIsEqual(t *testing.T) {
	meta1 := PeerSystemMeta{
		NetworkAddresses: []NetworkAddress{{
			NetIP: netip.MustParsePrefix("192.168.1.2/24"),
			Mac:   "2",
		},
			{
				NetIP: netip.MustParsePrefix("192.168.1.0/24"),
				Mac:   "1",
			},
		},
		Files: []File{
			{
				Path:             "/etc/hosts1",
				Exist:            true,
				ProcessIsRunning: true,
			},
			{
				Path:             "/etc/hosts2",
				Exist:            false,
				ProcessIsRunning: false,
			},
		},
	}
	meta2 := PeerSystemMeta{
		NetworkAddresses: []NetworkAddress{
			{
				NetIP: netip.MustParsePrefix("192.168.1.0/24"),
				Mac:   "1",
			},
			{
				NetIP: netip.MustParsePrefix("192.168.1.2/24"),
				Mac:   "2",
			},
		},
		Files: []File{
			{
				Path:             "/etc/hosts2",
				Exist:            false,
				ProcessIsRunning: false,
			},
			{
				Path:             "/etc/hosts1",
				Exist:            true,
				ProcessIsRunning: true,
			},
		},
	}
	if !meta1.isEqual(meta2) {
		t.Error("meta1 should be equal to meta2")
	}
}

func TestFlags_IsEqual(t *testing.T) {
	tests := []struct {
		name   string
		f1     Flags
		f2     Flags
		expect bool
	}{
		{
			name: "should be equal when all fields are identical",
			f1: Flags{
				RosenpassEnabled: true, RosenpassPermissive: false, ServerSSHAllowed: true,
				DisableClientRoutes: false, DisableServerRoutes: true, DisableDNS: false,
				DisableFirewall: true, BlockLANAccess: false, BlockInbound: true, LazyConnectionEnabled: true,
			},
			f2: Flags{
				RosenpassEnabled: true, RosenpassPermissive: false, ServerSSHAllowed: true,
				DisableClientRoutes: false, DisableServerRoutes: true, DisableDNS: false,
				DisableFirewall: true, BlockLANAccess: false, BlockInbound: true, LazyConnectionEnabled: true,
			},
			expect: true,
		},
		{
			name: "shouldn't be equal when fields are different",
			f1: Flags{
				RosenpassEnabled: true, RosenpassPermissive: false, ServerSSHAllowed: true,
				DisableClientRoutes: false, DisableServerRoutes: true, DisableDNS: false,
				DisableFirewall: true, BlockLANAccess: false, BlockInbound: true, LazyConnectionEnabled: true,
			},
			f2: Flags{
				RosenpassEnabled: false, RosenpassPermissive: true, ServerSSHAllowed: false,
				DisableClientRoutes: true, DisableServerRoutes: false, DisableDNS: true,
				DisableFirewall: false, BlockLANAccess: true, BlockInbound: false, LazyConnectionEnabled: false,
			},
			expect: false,
		},
		{
			name:   "should be equal when both are empty",
			f1:     Flags{},
			f2:     Flags{},
			expect: true,
		},
		{
			name:   "shouldn't be equal when at least one field differs",
			f1:     Flags{RosenpassEnabled: true},
			f2:     Flags{RosenpassEnabled: false},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, tt.f1.isEqual(tt.f2))
		})
	}
}
