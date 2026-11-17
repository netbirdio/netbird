package nftables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertPrefixesToSetWildcard verifies that a /0 prefix produces a
// usable interval. The last address of a /0 is the broadcast, whose Next()
// overflows to an invalid Addr with an empty key; the IntervalEnd must wrap
// to the zero address instead so nftables sees a full-range interval.
func TestConvertPrefixesToSetWildcard(t *testing.T) {
	tests := []struct {
		name   string
		af     addrFamily
		prefix string
	}{
		{"IPv4 /0", afIPv4, "0.0.0.0/0"},
		{"IPv6 /0", afIPv6, "::/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &family{af: tt.af}
			elements := r.convertPrefixesToSet([]netip.Prefix{netip.MustParsePrefix(tt.prefix)})

			require.Len(t, elements, 2, "expected start and interval-end element")
			assert.False(t, elements[0].IntervalEnd, "first element is the interval start")
			assert.True(t, elements[1].IntervalEnd, "second element is the interval end")
			assert.Len(t, elements[1].Key, int(tt.af.addrLen), "interval-end key must be a zero address, not empty")
		})
	}
}
