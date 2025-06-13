//go:build android || freebsd || ios

package system

// updateStaticInfo returns an empty implementation for unsupported platforms
func updateStaticInfo() StaticInfo {
	return StaticInfo{}
}
