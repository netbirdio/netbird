package consoleuser

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

// activeUID returns the UID of the user currently logged into the macOS GUI
// console session. Uses SCDynamicStoreCopyConsoleUser from the
// SystemConfiguration framework via purego (no cgo).
func activeUID() (uint32, bool) {
	sc, err := purego.Dlopen(
		"/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",
		purego.RTLD_NOW|purego.RTLD_GLOBAL,
	)
	if err != nil {
		return 0, false
	}

	cf, err := purego.Dlopen(
		"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
		purego.RTLD_NOW|purego.RTLD_GLOBAL,
	)
	if err != nil {
		return 0, false
	}

	// CFStringRef SCDynamicStoreCopyConsoleUser(SCDynamicStoreRef store,
	//     uid_t *uid, gid_t *gid);
	//
	// We pass nil for the store (NULL is accepted; the framework creates a
	// transient one), discard the returned CFStringRef username (we only
	// need the UID), and read uid via the out-pointer.
	var copyConsoleUser func(store uintptr, uidPtr, gidPtr unsafe.Pointer) uintptr
	purego.RegisterLibFunc(&copyConsoleUser, sc, "SCDynamicStoreCopyConsoleUser")

	var cfRelease func(uintptr)
	purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")

	var uid uint32
	var gid uint32

	cfStr := copyConsoleUser(0, unsafe.Pointer(&uid), unsafe.Pointer(&gid))
	if cfStr == 0 {
		return 0, false
	}
	cfRelease(cfStr)

	// loginwindow / no GUI session reports uid 0. We don't want the
	// console-user path to grant anything to root (root is already always
	// allowed by the interceptor), so treat uid 0 as "no console user".
	if uid == 0 {
		return 0, false
	}

	return uid, true
}
