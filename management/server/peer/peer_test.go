package peer

import (
	"fmt"
	"net/netip"
	"testing"
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
