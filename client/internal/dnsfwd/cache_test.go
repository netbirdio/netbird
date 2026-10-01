package dnsfwd

import (
	"net/netip"
	"testing"
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
	c.set(domainInput, 1 /* dns.TypeA */, ipv4)

	// Lookup with lower, with trailing dot
	if got, ok := c.get("example.com.", 1); !ok || len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Fatalf("expected cached IPv4 result via normalized key, got=%v ok=%v", got, ok)
	}

	// Lookup with different casing again
	if got, ok := c.get("EXAMPLE.COM", 1); !ok || len(got) != 1 || got[0].String() != "1.2.3.4" {
		t.Fatalf("expected cached IPv4 result via different casing, got=%v ok=%v", got, ok)
	}
}

func TestCacheSeparateTypes(t *testing.T) {
	c := newCache()

	domain := "test.local"
	ipv4 := []netip.Addr{mustAddr(t, "10.0.0.1")}
	ipv6 := []netip.Addr{mustAddr(t, "2001:db8::1")}

	c.set(domain, 1 /* A */, ipv4)
	c.set(domain, 28 /* AAAA */, ipv6)

	got4, ok4 := c.get(domain, 1)
	if !ok4 || len(got4) != 1 || got4[0] != ipv4[0] {
		t.Fatalf("expected A record from cache, got=%v ok=%v", got4, ok4)
	}

	got6, ok6 := c.get(domain, 28)
	if !ok6 || len(got6) != 1 || got6[0] != ipv6[0] {
		t.Fatalf("expected AAAA record from cache, got=%v ok=%v", got6, ok6)
	}
}

func TestCacheCloneOnGetAndSet(t *testing.T) {
	c := newCache()
	domain := "clone.test"

	src := []netip.Addr{mustAddr(t, "8.8.8.8")}
	c.set(domain, 1, src)

	// Mutate source slice; cache should be unaffected
	src[0] = mustAddr(t, "9.9.9.9")

	got, ok := c.get(domain, 1)
	if !ok || len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatalf("expected cached value to be independent of source slice, got=%v ok=%v", got, ok)
	}

	// Mutate returned slice; internal cache should remain unchanged
	got[0] = mustAddr(t, "4.4.4.4")
	got2, ok2 := c.get(domain, 1)
	if !ok2 || len(got2) != 1 || got2[0].String() != "8.8.8.8" {
		t.Fatalf("expected returned slice to be a clone, got=%v ok=%v", got2, ok2)
	}
}

func TestCacheMiss(t *testing.T) {
	c := newCache()
	if got, ok := c.get("missing.example", 1); ok || got != nil {
		t.Fatalf("expected cache miss, got=%v ok=%v", got, ok)
	}
}
