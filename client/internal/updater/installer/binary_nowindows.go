//go:build !windows

package installer

func UpdaterBinaryNameWithoutExtension() string {
	return updaterBinary
}
