//go:build freebsd

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The row pitch decides where every row after the first begins, so getting it
// from the reported width instead of the mapping shears the whole image on any
// device that pads its rows.
func TestFreebsdFBStride(t *testing.T) {
	tests := []struct {
		name    string
		fbt     fbType
		want    int
		wantErr bool
	}{
		{
			name: "unpadded 32bpp",
			fbt:  fbType{FbWidth: 1920, FbHeight: 1080, FbDepth: 32, FbSize: 1920 * 4 * 1080},
			want: 1920 * 4,
		},
		{
			name: "row padded up to an alignment",
			fbt:  fbType{FbWidth: 1366, FbHeight: 768, FbDepth: 32, FbSize: 5504 * 768},
			want: 5504, // 1366*4 = 5464, padded to 5504
		},
		{
			name: "unpadded 16bpp",
			fbt:  fbType{FbWidth: 800, FbHeight: 600, FbDepth: 16, FbSize: 800 * 2 * 600},
			want: 800 * 2,
		},
		{
			// A mapping too small for the geometry it reports: reading rows at
			// the reported width would run off the end of it.
			name:    "size cannot hold the geometry",
			fbt:     fbType{FbWidth: 1920, FbHeight: 1080, FbDepth: 32, FbSize: 1920 * 4 * 500},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := freebsdFBStride(tt.fbt)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.GreaterOrEqual(t, got, int(tt.fbt.FbWidth)*(int(tt.fbt.FbDepth)/8),
				"the pitch can pad a row but never truncate it")
		})
	}
}
