package cmd

import "context"

// SetupDebugHandler is a no-op for WASM
func SetupDebugHandler(context.Context, interface{}, interface{}, interface{}, string) {
	// Debug handler not needed for WASM
}
