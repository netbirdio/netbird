package posture

import (
	"context"
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
			name: "darwin with matching running processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					Files: []peer.File{
						{Path: "/Applications/process1.app", ProcessIsRunning: true},
						{Path: "/Applications/process2.app", ProcessIsRunning: true},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{MacPath: "/Applications/process1.app"},
					{MacPath: "/Applications/process2.app"},
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
					Files: []peer.File{
						{Path: "/Applications/process1.app", ProcessIsRunning: true},
						{Path: "/Applications/process2.app", ProcessIsRunning: true},
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
			name: "linux with matching running processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					Files: []peer.File{
						{Path: "/usr/bin/process1", ProcessIsRunning: true},
						{Path: "/usr/bin/process2", ProcessIsRunning: true},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{LinuxPath: "/usr/bin/process1"},
					{LinuxPath: "/usr/bin/process2"},
				},
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "linux with matching no running processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					Files: []peer.File{
						{Path: "/usr/bin/process1", ProcessIsRunning: true},
						{Path: "/usr/bin/process2", ProcessIsRunning: false},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{LinuxPath: "/usr/bin/process1"},
					{LinuxPath: "/usr/bin/process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "linux with windows process paths",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					Files: []peer.File{
						{Path: "/usr/bin/process1", ProcessIsRunning: true},
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
					Files: []peer.File{
						{Path: "/usr/bin/process3"},
						{Path: "/usr/bin/process4"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{LinuxPath: "/usr/bin/process1"},
					{LinuxPath: "/usr/bin/process2"},
				},
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "windows with matching running processes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					Files: []peer.File{
						{Path: "C:\\Program Files\\process1.exe", ProcessIsRunning: true},
						{Path: "C:\\Program Files\\process1.exe", ProcessIsRunning: true},
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
					Files: []peer.File{
						{Path: "C:\\Program Files\\process1.exe"},
						{Path: "C:\\Program Files\\process1.exe"},
					},
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{MacPath: "/Applications/process1.app"},
					{LinuxPath: "/Applications/process2.app"},
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
					Files: []peer.File{
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
					{WindowsPath: "C:\\Program Files\\process1.exe"},
					{MacPath: "/Applications/process2.app"},
				},
			},
			wantErr: true,
			isValid: false,
		},
		{
			name: "unsupported android operating system",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "android",
				},
			},
			check: ProcessCheck{
				Processes: []Process{
					{WindowsPath: "C:\\Program Files\\process1.exe"},
					{MacPath: "/Applications/process2.app"},
					{LinuxPath: "/usr/bin/process2"},
				},
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

func TestProcessCheck_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		check         ProcessCheck
		expectedError bool
	}{
		{
			name: "Valid linux, mac and windows processes",
			check: ProcessCheck{
				Processes: []Process{
					{
						LinuxPath:   "/usr/local/bin/netbird",
						MacPath:     "/usr/local/bin/netbird",
						WindowsPath: "C:\\ProgramData\\NetBird\\netbird.exe",
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Valid linux process",
			check: ProcessCheck{
				Processes: []Process{
					{
						LinuxPath: "/usr/local/bin/netbird",
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Valid mac process",
			check: ProcessCheck{
				Processes: []Process{
					{
						MacPath: "/Applications/NetBird.app/Contents/MacOS/netbird",
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
