package manager_test

import (
	"net/netip"
	"reflect"
	"regexp"
	"testing"

	"github.com/netbirdio/netbird/client/firewall/manager"
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

		result1 := manager.GenerateSetName(prefixes1)
		result2 := manager.GenerateSetName(prefixes2)

		if result1 != result2 {
			t.Errorf("Different orders produced different hashes: %s != %s", result1, result2)
		}
	})

	t.Run("Result format is correct", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}

		result := manager.GenerateSetName(prefixes)

		matched, err := regexp.MatchString(`^nb-[0-9a-f]{8}$`, result)
		if err != nil {
			t.Fatalf("Error matching regex: %v", err)
		}
		if !matched {
			t.Errorf("Result format is incorrect: %s", result)
		}
	})

	t.Run("Empty input produces consistent result", func(t *testing.T) {
		result1 := manager.GenerateSetName([]netip.Prefix{})
		result2 := manager.GenerateSetName([]netip.Prefix{})

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

		result1 := manager.GenerateSetName(prefixes1)
		result2 := manager.GenerateSetName(prefixes2)

		if result1 != result2 {
			t.Errorf("Different orders of IPv4 and IPv6 produced different hashes: %s != %s", result1, result2)
		}
	})
}

func TestMergeIPRanges(t *testing.T) {
	tests := []struct {
		name     string
		input    []netip.Prefix
		expected []netip.Prefix
	}{
		{
			name:     "Empty input",
			input:    []netip.Prefix{},
			expected: []netip.Prefix{},
		},
		{
			name: "Single range",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "Two non-overlapping ranges",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("10.0.0.0/8"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("10.0.0.0/8"),
			},
		},
		{
			name: "One range containing another",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
		{
			name: "One range containing another (different order)",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
		{
			name: "Overlapping ranges",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("192.168.1.128/25"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "Overlapping ranges (different order)",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.128/25"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "Multiple overlapping ranges",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("192.168.2.0/24"),
				netip.MustParsePrefix("192.168.1.128/25"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
		{
			name: "Partially overlapping ranges",
			input: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/23"),
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("192.168.2.0/25"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/23"),
				netip.MustParsePrefix("192.168.2.0/25"),
			},
		},
		{
			name: "IPv6 ranges",
			input: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
				netip.MustParsePrefix("2001:db8:1::/48"),
				netip.MustParsePrefix("2001:db8:2::/48"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.MergeIPRanges(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("MergeIPRanges() = %v, want %v", result, tt.expected)
			}
		})
	}
}
