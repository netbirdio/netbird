//go:build !(linux || windows)

package net

func Init() {
	// nothing to do on non-linux
}

func AdvancedRouting() bool {
	// non-linux currently doesn't support advanced routing
	return false
}
