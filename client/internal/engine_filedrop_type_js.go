//go:build js

package internal

// fileDropManager keeps the engine and ConnectClient fields typed on wasm,
// where file drop is not supported and the manager is always nil. Aliasing a
// pointer keeps the nil guards and stays out of the filedrop package, so its
// HTTP server and client never reach the wasm binary.
type fileDropManager = *struct{}
