package inspect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadVarInt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint64
		n    int
	}{
		{
			name: "1 byte value",
			data: []byte{0x25},
			want: 37,
			n:    1,
		},
		{
			name: "2 byte value",
			data: []byte{0x7b, 0xbd},
			want: 15293,
			n:    2,
		},
		{
			name: "4 byte value",
			data: []byte{0x9d, 0x7f, 0x3e, 0x7d},
			want: 494878333,
			n:    4,
		},
		{
			name: "zero",
			data: []byte{0x00},
			want: 0,
			n:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, n, err := readVarInt(tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, val)
			assert.Equal(t, tt.n, n)
		})
	}
}

func TestReadVarInt_Empty(t *testing.T) {
	_, _, err := readVarInt(nil)
	require.Error(t, err)
}

func TestReadVarInt_Truncated(t *testing.T) {
	// 2-byte prefix but only 1 byte
	_, _, err := readVarInt([]byte{0x40})
	require.Error(t, err)
}

func TestExtractQUICSNI_NotLongHeader(t *testing.T) {
	// Short header packet (form bit not set)
	data := make([]byte, 100)
	data[0] = 0x40 // short header

	_, err := ExtractQUICSNI(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a QUIC long header")
}

func TestExtractQUICSNI_UnsupportedVersion(t *testing.T) {
	data := make([]byte, 100)
	data[0] = 0xC0 // long header
	// Version 0xdeadbeef
	data[1] = 0xde
	data[2] = 0xad
	data[3] = 0xbe
	data[4] = 0xef

	_, err := ExtractQUICSNI(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported QUIC version")
}

func TestExtractQUICSNI_TooShort(t *testing.T) {
	_, err := ExtractQUICSNI([]byte{0xC0, 0x00})
	require.Error(t, err)
}

func TestHkdfExpandLabel(t *testing.T) {
	// Smoke test: ensure it returns the right length and doesn't error
	secret := make([]byte, 32)
	result, err := hkdfExpandLabel(secret, "quic key", nil, 16)
	require.NoError(t, err)
	assert.Len(t, result, 16)
}
