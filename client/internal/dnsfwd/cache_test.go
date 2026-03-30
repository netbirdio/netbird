package dnsfwd

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %s: %v", s, err)
	}
	return a
}

func TestCacheNormalization(t *testing.T) {
	c := newCache()

	// Mixed case, without trailing dot
	domainInput := "ExAmPlE.CoM"
	ipv4 := []netip.Addr{mustAddr(t, "1.2.3.4")}
	c.set(domainInput, dns.TypeA, ipv4)

	// Lookup with lower, with trailing dot
	if got, ok := c.get("example.com.", dns.TypeA); !ok || len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Fatalf("expected cached IPv4 result via normalized key, got=%v ok=%v", got, ok)
	}

	// Lookup with different casing again
	if got, ok := c.get("EXAMPLE.COM", dns.TypeA); !ok || len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Fatalf("expected cached IPv4 result via different casing, got=%v ok=%v", got, ok)
	}
}

func TestCacheSeparateTypes(t *testing.T) {
	c := newCache()

	domain := "test.local"
	ipv4 := []netip.Addr{mustAddr(t, "10.0.0.1")}
	ipv6 := []netip.Addr{mustAddr(t, "2001:db8::1")}

	c.set(domain, dns.TypeA, ipv4)
	c.set(domain, dns.TypeAAAA, ipv6)

	got4, ok4 := c.get(domain, dns.TypeA)
	if !ok4 || len(got4) != 1 || got4[0] != ipv4[0] {
		t.Fatalf("expected A record from cache, got=%v ok=%v", got4, ok4)
	}

	got6, ok6 := c.get(domain, dns.TypeAAAA)
	if !ok6 || len(got6) != 1 || got6[0] != ipv6[0] {
		t.Fatalf("expected AAAA record from cache, got=%v ok=%v", got6, ok6)
	}
}

func TestCacheCloneOnGetAndSet(t *testing.T) {
	c := newCache()
	domain := "clone.test"

	src := []netip.Addr{mustAddr(t, "8.8.8.8")}
	c.set(domain, dns.TypeA, src)

	// Mutate source slice; cache should be unaffected
	src[0] = mustAddr(t, "9.9.9.9")

	got, ok := c.get(domain, dns.TypeA)
	if !ok || len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatalf("expected cached value to be independent of source slice, got=%v ok=%v", got, ok)
	}

	// Mutate returned slice; internal cache should remain unchanged
	got[0] = mustAddr(t, "4.4.4.4")
	got2, ok2 := c.get(domain, dns.TypeA)
	if !ok2 || len(got2) != 1 || got2[0].String() != "8.8.8.8" {
		t.Fatalf("expected returned slice to be a clone, got=%v ok=%v", got2, ok2)
	}
}

func TestCacheMiss(t *testing.T) {
	c := newCache()
	if got, ok := c.get("missing.example", dns.TypeA); ok || got != nil {
		t.Fatalf("expected cache miss, got=%v ok=%v", got, ok)
	}
}

func TestCacheFlush(t *testing.T) {
	c := newCache()

	ipv4 := []netip.Addr{mustAddr(t, "1.2.3.4")}
	ipv6 := []netip.Addr{mustAddr(t, "2001:db8::1")}

	c.set("foo.example.com", dns.TypeA, ipv4)
	c.set("bar.example.com", dns.TypeAAAA, ipv6)

	// Confirm entries exist before flush
	if _, ok := c.get("foo.example.com", dns.TypeA); !ok {
		t.Fatal("expected foo.example.com A record before flush")
	}
	if _, ok := c.get("bar.example.com", dns.TypeAAAA); !ok {
		t.Fatal("expected bar.example.com AAAA record before flush")
	}

	c.flush()

	// All entries should be gone after flush
	if got, ok := c.get("foo.example.com", dns.TypeA); ok || got != nil {
		t.Fatalf("expected cache miss for foo.example.com after flush, got=%v ok=%v", got, ok)
	}
	if got, ok := c.get("bar.example.com", dns.TypeAAAA); ok || got != nil {
		t.Fatalf("expected cache miss for bar.example.com after flush, got=%v ok=%v", got, ok)
	}
}

func TestCacheFlushEmpty(t *testing.T) {
	c := newCache()
	// Flushing an empty cache should not panic
	c.flush()
	if got, ok := c.get("any.domain", dns.TypeA); ok || got != nil {
		t.Fatalf("expected empty cache after flush, got=%v ok=%v", got, ok)
	}
}
