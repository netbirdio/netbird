package netiputil

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodePrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		size   int
	}{
		{
			name:   "v4 host",
			prefix: "100.64.0.1/32",
			size:   5,
		},
		{
			name:   "v4 network",
			prefix: "10.0.0.0/8",
			size:   5,
		},
		{
			name:   "v4 default",
			prefix: "0.0.0.0/0",
			size:   5,
		},
		{
			name:   "v6 host",
			prefix: "fd00::1/128",
			size:   17,
		},
		{
			name:   "v6 network",
			prefix: "fd00:1234:5678::/48",
			size:   17,
		},
		{
			name:   "v6 default",
			prefix: "::/0",
			size:   17,
		},
		{
			name:   "v4 /16 overlay",
			prefix: "100.64.0.1/16",
			size:   5,
		},
		{
			name:   "v6 /64 overlay",
			prefix: "fd00::abcd:1/64",
			size:   17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			b := EncodePrefix(p)
			assert.Equal(t, tt.size, len(b), "encoded size")

			decoded, err := DecodePrefix(b)
			require.NoError(t, err)
			assert.Equal(t, p, decoded)
		})
	}
}

func TestEncodePrefixUnmaps(t *testing.T) {
	// v4-mapped v6 address should encode as v4
	mapped := netip.MustParsePrefix("::ffff:10.1.2.3/32")
	b := EncodePrefix(mapped)
	assert.Equal(t, 5, len(b), "v4-mapped should encode as 5 bytes")

	decoded, err := DecodePrefix(b)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("10.1.2.3/32"), decoded)
}

func TestEncodePrefixUnmapsClampsBits(t *testing.T) {
	// v4-mapped v6 with bits > 32 should clamp to /32
	mapped := netip.MustParsePrefix("::ffff:10.1.2.3/128")
	b := EncodePrefix(mapped)
	assert.Equal(t, 5, len(b), "v4-mapped should encode as 5 bytes")

	decoded, err := DecodePrefix(b)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("10.1.2.3/32"), decoded)

	// v4-mapped v6 with bits=96 should also clamp to /32
	mapped96 := netip.MustParsePrefix("::ffff:10.0.0.0/96")
	b96 := EncodePrefix(mapped96)
	assert.Equal(t, 5, len(b96))

	decoded96, err := DecodePrefix(b96)
	require.NoError(t, err)
	assert.Equal(t, 32, decoded96.Bits())
}

func TestDecodeAddr(t *testing.T) {
	v4 := netip.MustParseAddr("100.64.0.5")
	b := EncodeAddr(v4)
	assert.Equal(t, 5, len(b))

	got, err := DecodeAddr(b)
	require.NoError(t, err)
	assert.Equal(t, v4, got)

	v6 := netip.MustParseAddr("fd00::1")
	b = EncodeAddr(v6)
	assert.Equal(t, 17, len(b))

	got, err = DecodeAddr(b)
	require.NoError(t, err)
	assert.Equal(t, v6, got)
}

func TestDecodePrefixInvalidLength(t *testing.T) {
	_, err := DecodePrefix([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid compact prefix length 3")

	_, err = DecodePrefix(nil)
	assert.Error(t, err)

	_, err = DecodePrefix([]byte{})
	assert.Error(t, err)
}

func TestDecodePrefixInvalidBits(t *testing.T) {
	// v4 with bits > 32
	b := []byte{10, 0, 0, 1, 33}
	_, err := DecodePrefix(b)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IPv4 prefix length 33")

	// v6 with bits > 128
	b = make([]byte, 17)
	b[0] = 0xfd
	b[16] = 129
	_, err = DecodePrefix(b)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IPv6 prefix length 129")
}

func TestDecodePrefixUnmapsV6Input(t *testing.T) {
	// If someone encodes a v4-mapped v6 as 17 bytes, decode should unmap it
	// and clamp the prefix length to 32 for v4
	addr := netip.MustParseAddr("::ffff:192.168.1.1")

	raw := addr.As16()
	b := make([]byte, 17)
	copy(b, raw[:])
	b[16] = 128

	decoded, err := DecodePrefix(b)
	require.NoError(t, err)
	assert.True(t, decoded.Addr().Is4(), "should be unmapped to v4")
	assert.Equal(t, netip.MustParsePrefix("192.168.1.1/32"), decoded)
}
