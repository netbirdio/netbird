package winregistry

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	advapi          = syscall.NewLazyDLL("advapi32.dll")
	regCreateKeyExW = advapi.NewProc("RegCreateKeyExW")
)

const (
	// Registry key options
	regOptionNonVolatile = 0x0 // Key is preserved when system is rebooted
	regOptionVolatile    = 0x1 // Key is not preserved when system is rebooted

	// Registry disposition values
	regCreatedNewKey     = 0x1
	regOpenedExistingKey = 0x2
)

// CreateVolatileKey creates a volatile registry key named path under open key root.
// CreateVolatileKey returns the new key and a boolean flag that reports whether the key already existed.
// The access parameter specifies the access rights for the key to be created.
//
// Volatile keys are stored in memory and are automatically deleted when the system is shut down.
// This provides automatic cleanup without requiring manual registry maintenance.
func CreateVolatileKey(root registry.Key, path string, access uint32) (registry.Key, bool, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false, err
	}

	var (
		handle      syscall.Handle
		disposition uint32
	)

	ret, _, _ := regCreateKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(pathPtr)),
		0,                          // reserved
		0,                          // class
		uintptr(regOptionVolatile), // options - volatile key
		uintptr(access),            // desired access
		0,                          // security attributes
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&disposition)),
	)

	if ret != 0 {
		return 0, false, syscall.Errno(ret)
	}

	return registry.Key(handle), disposition == regOpenedExistingKey, nil
}
