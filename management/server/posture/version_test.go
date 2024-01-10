package posture

import (
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
	}{
		{
			name: "Valid Peer NB version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "1.0.1",
				},
			},
			check: NBVersionCheck{
				Enabled:    true,
				MinVersion: "1.0.0",
			},
			wantErr: false,
		},
		{
			name: "Valid Peer NB version With No Patch Version 1",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "2.0.9",
				},
			},
			check: NBVersionCheck{
				Enabled:    true,
				MinVersion: "2.0",
			},
			wantErr: false,
		},
		{
			name: "Valid Peer NB version With No Patch Version 2",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "2.0.0",
				},
			},
			check: NBVersionCheck{
				Enabled:    true,
				MinVersion: "2.0",
			},
			wantErr: false,
		},
		{
			name: "Older Peer NB version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "0.9.9",
				},
			},
			check: NBVersionCheck{
				Enabled:    true,
				MinVersion: "1.0.0",
			},
			wantErr: true,
		},
		{
			name: "Older Peer NB version With Patch Version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "0.1.0",
				},
			},
			check: NBVersionCheck{
				Enabled:    true,
				MinVersion: "0.2",
			},
			wantErr: true,
		},
		{
			name: "Older Peer NB version With Check Disabled",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "0.0.9",
				},
			},
			check: NBVersionCheck{
				Enabled:    false,
				MinVersion: "1.0.0",
			},
			wantErr: false,
		},
		{
			name: "Invalid Peer NB version",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					UIVersion: "x.y.z",
				},
			},
			check: NBVersionCheck{
				Enabled:    true,
				MinVersion: "1.0.0",
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
