//go:build js

package server

// validateUsername is not supported on JS/WASM
func validateUsername(_ string) error {
	return errNotSupported
}
