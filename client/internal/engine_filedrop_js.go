//go:build js

package internal

// File drop is not supported on wasm: there is no local filesystem to deliver
// into and no way to bind a receiver. The engine still calls these on the
// start, stop and overlay rebind paths, so they exist as no-ops and keep the
// filedrop package out of the wasm binary.

func (e *Engine) startFileDrop() {}

func (e *Engine) stopFileDrop() {}

func (e *Engine) restartFileDrop() error { return nil }
