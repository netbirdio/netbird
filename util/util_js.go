//go:build js

package util

// IsAdmin returns false for WASM as there's no admin concept in browser
func IsAdmin() bool {
	return false
}
