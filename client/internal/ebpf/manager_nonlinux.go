//go:build !linux || android

package ebpf

// GetEbpfManagerInstance return error because ebpf is not supported on all os
func GetEbpfManagerInstance() Manager {
	panic("unsupported os")
}
