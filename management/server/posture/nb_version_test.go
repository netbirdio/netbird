package posture

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/server/peer"

	"github.com/stretchr/testify/assert"
)

func TestNBVersionCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		input   peer.Peer
		check   NBVersionCheck
		wantErr bool
		isValid bool
	}{
		{
			name: "Valid Peer NB version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					WtVersion: "1.0.1",
				},
			},
			check: NBVersionCheck{
				MinVersion: "1.0.0",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Valid Peer NB version With No Patch Version 1",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					WtVersion: "2.0.9",
				},
			},
			check: NBVersionCheck{
				MinVersion: "2.0",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Valid Peer NB version With No Patch Version 2",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					WtVersion: "2.0.0",
				},
			},
			check: NBVersionCheck{
				MinVersion: "2.0",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Older Peer NB version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					WtVersion: "0.9.9",
				},
			},
			check: NBVersionCheck{
				MinVersion: "1.0.0",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Older Peer NB version With Patch Version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					WtVersion: "0.1.0",
				},
			},
			check: NBVersionCheck{
				MinVersion: "0.2",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Invalid Peer NB version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					WtVersion: "x.y.z",
				},
			},
			check: NBVersionCheck{
				MinVersion: "1.0.0",
			},
			wantErr: true,
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid, err := tt.check.Check(context.Background(), tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

func TestNBVersionCheck_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		check         NBVersionCheck
		expectedError bool
	}{
		{
			name:          "Valid NBVersionCheck",
			check:         NBVersionCheck{MinVersion: "1.0"},
			expectedError: false,
		},
		{
			name:          "Invalid NBVersionCheck",
			check:         NBVersionCheck{},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.check.Validate()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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
