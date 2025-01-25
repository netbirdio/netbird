package types

import (
	"net/netip"
	"regexp"
	"testing"
)

func TestGenerateSetName(t *testing.T) {
	t.Run("Different orders result in same hash", func(t *testing.T) {
		prefixes1 := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}
		prefixes2 := []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.168.1.0/24"),
		}

		result1 := GenerateSetName(prefixes1)
		result2 := GenerateSetName(prefixes2)

		if result1 != result2 {
			t.Errorf("Different orders produced different hashes: %s != %s", result1, result2)
		}
	})

	t.Run("Result format is correct", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}

		result := GenerateSetName(prefixes)

		matched, err := regexp.MatchString(`^nb-[0-9a-f]{8}$`, result)
		if err != nil {
			t.Fatalf("Error matching regex: %v", err)
		}
		if !matched {
			t.Errorf("Result format is incorrect: %s", result)
		}
	})

	t.Run("Empty input produces consistent result", func(t *testing.T) {
		result1 := GenerateSetName([]netip.Prefix{})
		result2 := GenerateSetName([]netip.Prefix{})

		if result1 != result2 {
			t.Errorf("Empty input produced inconsistent results: %s != %s", result1, result2)
		}
	})

	t.Run("IPv4 and IPv6 mixing", func(t *testing.T) {
		prefixes1 := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("2001:db8::/32"),
		}
		prefixes2 := []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/32"),
			netip.MustParsePrefix("192.168.1.0/24"),
		}

		result1 := GenerateSetName(prefixes1)
		result2 := GenerateSetName(prefixes2)

		if result1 != result2 {
			t.Errorf("Different orders of IPv4 and IPv6 produced different hashes: %s != %s", result1, result2)
		}
	})
}
