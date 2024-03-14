package posture

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/peer"
)

func TestProcessCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		input   peer.Peer
		check   ProcessCheck
		wantErr bool
		isValid bool
	}{
		{
			name: "darwin with matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					Processes: []peer.Process{
						{Path: "process1"},
						{Path: "process2"}},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "process1"},
					{Path: "process2"},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "darwin with windows process paths",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					Processes: []peer.Process{
						{Path: "process1"},
						{Path: "process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "process1"},
					{WindowsPath: "process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "linux with matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					Processes: []peer.Process{
						{Path: "process1"},
						{Path: "process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "process1"},
					{Path: "process2"},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "linux with windows process paths",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					Processes: []peer.Process{
						{Path: "process1"},
						{Path: "process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "process1"},
					{WindowsPath: "process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "linux with non-matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					Processes: []peer.Process{
						{Path: "process3"},
						{Path: "process4"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "process1"},
					{Path: "process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "windows with matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					Processes: []peer.Process{
						{Path: "process1"},
						{Path: "process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "process1"},
					{WindowsPath: "process2"},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "windows with darwin process paths",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					Processes: []peer.Process{
						{Path: "process1"},
						{Path: "process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "process1"},
					{Path: "process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "windows with non-matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					Processes: []peer.Process{
						{Path: "process3"},
						{Path: "process4"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "process1"},
					{WindowsPath: "process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "unsupported ios operating system with matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "ios",
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "process1"},
					{Path: "process2"},
				},
			},
			wantErr: true,
			isValid: false,
		},
		{
			name: "unsupported android operating system with matching processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "android",
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "process1"},
					{Path: "process2"},
				},
			},
			wantErr: true,
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
