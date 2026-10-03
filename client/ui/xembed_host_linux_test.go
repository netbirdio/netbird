//go:build linux && !gtk3 && !(linux && 386)

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIconPixmapValidate(t *testing.T) {
	tests := []struct {
		name  string
		icon  iconPixmap
		valid bool
	}{
		{"well formed", iconPixmap{W: 2, H: 2, Pix: make([]byte, 16)}, true},
		{"trailing frames are allowed", iconPixmap{W: 2, H: 2, Pix: make([]byte, 64)}, true},
		{"buffer shorter than claimed", iconPixmap{W: 2, H: 2, Pix: make([]byte, 15)}, false},
		{"no pixels", iconPixmap{W: 2, H: 2}, false},
		{"zero size", iconPixmap{W: 0, H: 0}, false},
		{"negative size", iconPixmap{W: -1, H: 2, Pix: make([]byte, 16)}, false},
		{"beyond the dimension bound", iconPixmap{W: maxIconPixmapDim + 1, H: 1, Pix: make([]byte, 16)}, false},
		// Dimensions this large would overflow the W*H*4 size arithmetic on a
		// 32-bit build; the bound rejects them before it is ever evaluated.
		{"dimensions beyond any plausible icon", iconPixmap{W: 1 << 15, H: 1 << 15, Pix: make([]byte, 16)}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.icon.validate()
			if tc.valid {
				require.NoError(t, err)
				return
			}
			assert.Error(t, err, "%dx%d with %d bytes must be rejected", tc.icon.W, tc.icon.H, len(tc.icon.Pix))
		})
	}
}
