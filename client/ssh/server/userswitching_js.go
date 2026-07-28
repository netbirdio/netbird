//go:build js

package server

// enableUserSwitching is not supported on JS/WASM
func enableUserSwitching() error {
	return errNotSupported
}
