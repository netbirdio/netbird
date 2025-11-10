package iface

// Destroy is a no-op on WASM
func (w *WGIface) Destroy() error {
	return nil
}
