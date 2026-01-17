//go:build android || ios || freebsd || js

package system

import "context"

// detectDiskEncryption is a stub for unsupported platforms.
func detectDiskEncryption(_ context.Context) DiskEncryptionInfo {
	return DiskEncryptionInfo{}
}
