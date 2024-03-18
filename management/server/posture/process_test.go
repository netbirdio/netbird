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
						{Path: "/Applications/process1.app"},
						{Path: "/Applications/process2.app"}},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "/Applications/process1.app"},
					{Path: "/Applications/process2.app"},
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
						{Path: "/Applications/process1.app"},
						{Path: "/Applications/process2.app"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "C:\\Program Files\\process1.exe"},
					{WindowsPath: "C:\\Program Files\\process2.exe"},
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
						{Path: "/usr/bin/process1"},
						{Path: "/usr/bin/process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "/usr/bin/process1"},
					{Path: "/usr/bin/process2"},
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
						{Path: "/usr/bin/process1"},
						{Path: "/usr/bin/process2"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "C:\\Program Files\\process1.exe"},
					{WindowsPath: "C:\\Program Files\\process2.exe"},
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
						{Path: "/usr/bin/process3"},
						{Path: "/usr/bin/process4"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "/usr/bin/process1"},
					{Path: "/usr/bin/process2"},
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
						{Path: "C:\\Program Files\\process1.exe"},
						{Path: "C:\\Program Files\\process1.exe"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "C:\\Program Files\\process1.exe"},
					{WindowsPath: "C:\\Program Files\\process1.exe"},
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
						{Path: "C:\\Program Files\\process1.exe"},
						{Path: "C:\\Program Files\\process1.exe"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "/Applications/process1.app"},
					{Path: "/Applications/process2.app"},
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
						{Path: "C:\\Program Files\\process3.exe"},
						{Path: "C:\\Program Files\\process4.exe"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "C:\\Program Files\\process1.exe"},
					{WindowsPath: "C:\\Program Files\\process2.exe"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "unsupported ios operating system",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "ios",
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{Path: "C:\\Program Files\\process1.exe"},
					{Path: "C:\\Program Files\\process2.exe"},
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
					{Path: "/usr/bin/process1"},
					{Path: "/usr/bin/process2"},
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

func TestProcessCheck_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		check         ProcessCheck
		expectedError bool
	}{
		{
			name: "Valid unix and windows processes",
			check: ProcessCheck{
				Processes: []Process{
					{
						Path:        "/usr/local/bin/netbird",
						WindowsPath: "C:\\ProgramData\\NetBird\\netbird.exe",
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Valid unix process",
			check: ProcessCheck{
				Processes: []Process{
					{
						Path: "/usr/local/bin/netbird",
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Valid windows process",
			check: ProcessCheck{
				Processes: []Process{
					{
						WindowsPath: "C:\\ProgramData\\NetBird\\netbird.exe",
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Invalid empty processes",
			check: ProcessCheck{
				Processes: []Process{},
			},
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
