package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMeetsMinVersion(t *testing.T) {
	tests := []struct {
		name    string
		minVer  string
		peerVer string
		want    bool
		wantErr bool
	}{
		{
			name:    "Peer version greater than min version",
			minVer:  "0.26.0",
			peerVer: "0.60.1",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Peer version equals min version",
			minVer:  "1.0.0",
			peerVer: "1.0.0",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Peer version less than min version",
			minVer:  "1.0.0",
			peerVer: "0.9.9",
			want:    false,
			wantErr: false,
		},
		{
			name:    "Peer version with pre-release tag greater than min version",
			minVer:  "1.0.0",
			peerVer: "1.0.1-alpha",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Invalid peer version format",
			minVer:  "1.0.0",
			peerVer: "dev",
			want:    false,
			wantErr: true,
		},
		{
			name:    "Invalid min version format",
			minVer:  "invalid.version",
			peerVer: "1.0.0",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MeetsMinVersion(tt.minVer, tt.peerVer)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
