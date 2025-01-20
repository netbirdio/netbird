//go:build !linux || android

package net

func Init() {
}

func AdvancedRouting() bool {
	// non-linux currently doesn't support advanced routing
	return false
}
