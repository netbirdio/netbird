package posture

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/peer"
)

func TestDiskEncryptionCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		input   peer.Peer
		check   DiskEncryptionCheck
		wantErr bool
		isValid bool
	}{
		{
			name: "linux with encrypted root",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "/", Encrypted: true},
							{Path: "/home", Encrypted: true},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				LinuxPath: "/",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "linux with unencrypted root",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "/", Encrypted: false},
							{Path: "/home", Encrypted: true},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				LinuxPath: "/",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "linux with no volume info",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS:           "linux",
					DiskEncryption: peer.DiskEncryptionInfo{},
				},
			},
			check: DiskEncryptionCheck{
				LinuxPath: "/",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "darwin with encrypted root",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "/", Encrypted: true},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				DarwinPath: "/",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "darwin with unencrypted root",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "/", Encrypted: false},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				DarwinPath: "/",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "windows with encrypted C drive",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "C:", Encrypted: true},
							{Path: "D:", Encrypted: false},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				WindowsPath: "C:",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "windows with unencrypted C drive",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "C:", Encrypted: false},
							{Path: "D:", Encrypted: true},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				WindowsPath: "C:",
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
			check: DiskEncryptionCheck{
				LinuxPath:   "/",
				DarwinPath:  "/",
				WindowsPath: "C:",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "unsupported android operating system",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "android",
				},
			},
			check: DiskEncryptionCheck{
				LinuxPath:   "/",
				DarwinPath:  "/",
				WindowsPath: "C:",
			},
			wantErr: false,
			isValid: false,
		},
		{
			name: "linux peer with no linux path configured passes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "linux",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "/", Encrypted: false},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				DarwinPath:  "/",
				WindowsPath: "C:",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "darwin peer with no darwin path configured passes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "darwin",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "/", Encrypted: false},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				LinuxPath:   "/",
				WindowsPath: "C:",
			},
			wantErr: false,
			isValid: true,
		},
		{
			name: "windows peer with no windows path configured passes",
			input: peer.Peer{
				Meta: peer.PeerSystemMeta{
					GoOS: "windows",
					DiskEncryption: peer.DiskEncryptionInfo{
						Volumes: []peer.DiskEncryptionVolume{
							{Path: "C:", Encrypted: false},
						},
					},
				},
			},
			check: DiskEncryptionCheck{
				LinuxPath:  "/",
				DarwinPath: "/",
			},
			wantErr: false,
			isValid: true,
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

func TestDiskEncryptionCheck_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		check         DiskEncryptionCheck
		expectedError bool
	}{
		{
			name: "valid linux, darwin and windows paths",
			check: DiskEncryptionCheck{
				LinuxPath:   "/",
				DarwinPath:  "/",
				WindowsPath: "C:",
			},
			expectedError: false,
		},
		{
			name: "valid linux path only",
			check: DiskEncryptionCheck{
				LinuxPath: "/",
			},
			expectedError: false,
		},
		{
			name: "valid darwin path only",
			check: DiskEncryptionCheck{
				DarwinPath: "/",
			},
			expectedError: false,
		},
		{
			name: "valid windows path only",
			check: DiskEncryptionCheck{
				WindowsPath: "C:",
			},
			expectedError: false,
		},
		{
			name:          "invalid empty paths",
			check:         DiskEncryptionCheck{},
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

func TestDiskEncryptionCheck_Name(t *testing.T) {
	check := DiskEncryptionCheck{}
	assert.Equal(t, DiskEncryptionCheckName, check.Name())
}
