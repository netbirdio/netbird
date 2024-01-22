package posture

import (
	"testing"

	"github.com/netbirdio/netbird/management/server/peer"

	"github.com/stretchr/testify/assert"
)

func TestOSVersionCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		input   peer.Peer
		check   OSVersionCheck
		wantErr bool
		isValid bool
	}{
		{
			name: "Valid Peer Linux Kernel version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.1.1",
				},
			},
			check: OSVersionCheck{
				Linux: &MinKernelVersionCheck{
					MinKernelVersion: "6.0.0",
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Not valid Peer macOS version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					Core: "14.2.1",
				},
			},
			check: OSVersionCheck{
				Darwin: &MinVersionCheck{
					MinVersion: "15",
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Valid Peer ios version allowed by any rule",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "ios",
					Core: "17.0.1",
				},
			},
			check: OSVersionCheck{
				Ios: &MinVersionCheck{
					MinVersion: "0",
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "Valid Peer android version not allowed by rule",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "android",
					Core: "14",
				},
			},
			check:   OSVersionCheck{},
			wantErr: false,
			isValid: false,
		},
		{
			name: "Valid Peer Linux Kernel version not allowed by rule",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS:          "linux",
					KernelVersion: "6.1.1",
				},
			},
			check:   OSVersionCheck{},
			wantErr: false,
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid, err := tt.check.Check(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}
