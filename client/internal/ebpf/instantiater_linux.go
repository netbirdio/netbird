//go:build !android

package ebpf

import (
	"github.com/netbirdio/netbird/client/internal/ebpf/ebpf"
	"github.com/netbirdio/netbird/client/internal/ebpf/manager"
)

// GetEbpfManagerInstance is a wrapper function. This encapsulation is required because if the code import the internal
// ebpf package the Go compiler will include the object files. But it is not supported on Android. It can cause instant
// panic on older Android version.
func GetEbpfManagerInstance() manager.Manager {
	return ebpf.GetEbpfManagerInstance()
}
