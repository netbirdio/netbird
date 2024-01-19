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
		},
		{
			name: "Valid Peer macOS version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					Core: "14.2.1",
				},
			},
			check: OSVersionCheck{
				Darwin: &MinVersionCheck{
					MinVersion: "13",
				},
			},
			wantErr: false,
		},
		{
			name: "No valid Peer macOS version",
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
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.check.Check(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
