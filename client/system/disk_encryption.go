package system

// DiskEncryptionVolume represents encryption status of a single volume.
type DiskEncryptionVolume struct {
	Path      string
	Encrypted bool
}

// DiskEncryptionInfo holds disk encryption detection results.
type DiskEncryptionInfo struct {
	Volumes []DiskEncryptionVolume
}

// IsEncrypted returns true if the volume at the given path is encrypted.
func (d DiskEncryptionInfo) IsEncrypted(path string) bool {
	for _, v := range d.Volumes {
		if v.Path == path {
			return v.Encrypted
		}
	}
	return false
}
