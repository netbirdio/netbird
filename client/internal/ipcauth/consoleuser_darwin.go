package ipcauth

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

// isConsoleUser reports whether id is the user currently logged into the macOS
// GUI console session. Uses SCDynamicStoreCopyConsoleUser from the
// SystemConfiguration framework via purego (no cgo).
func isConsoleUser(id Identity) bool {
	// A SID belongs to a Windows principal and has no uid to compare.
	if id.IsWindows() {
		return false
	}

	uid, ok := consoleUID()
	return ok && uid == id.UID
}

// consoleUID returns the uid of the GUI console session, and false when nobody
// is logged in at it.
func consoleUID() (uint32, bool) {
	sc, err := purego.Dlopen(
		"/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",
		purego.RTLD_NOW|purego.RTLD_GLOBAL,
	)
	if err != nil {
		return 0, false
	}
	defer func() {
		_ = purego.Dlclose(sc)
	}()

	cf, err := purego.Dlopen(
		"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
		purego.RTLD_NOW|purego.RTLD_GLOBAL,
	)
	if err != nil {
		return 0, false
	}
	defer func() {
		_ = purego.Dlclose(cf)
	}()

	// CFStringRef SCDynamicStoreCopyConsoleUser(SCDynamicStoreRef store,
	//     uid_t *uid, gid_t *gid);
	//
	// We pass nil for the store (NULL is accepted; the framework creates a
	// transient one), discard the returned CFStringRef username (we only
	// need the UID), and read uid via the out-pointer.
	copyConsoleUserSym, err := purego.Dlsym(sc, "SCDynamicStoreCopyConsoleUser")
	if err != nil {
		return 0, false
	}
	cfReleaseSym, err := purego.Dlsym(cf, "CFRelease")
	if err != nil {
		return 0, false
	}

	var copyConsoleUser func(store uintptr, uidPtr, gidPtr unsafe.Pointer) uintptr
	purego.RegisterFunc(&copyConsoleUser, copyConsoleUserSym)

	var cfRelease func(uintptr)
	purego.RegisterFunc(&cfRelease, cfReleaseSym)

	var uid uint32
	var gid uint32

	cfStr := copyConsoleUser(0, unsafe.Pointer(&uid), unsafe.Pointer(&gid))
	if cfStr == 0 {
		return 0, false
	}
	cfRelease(cfStr)

	// loginwindow / no GUI session reports uid 0. We don't want the
	// console-user path to grant anything to root, so treat uid 0 as "no
	// console user".
	if uid == 0 {
		return 0, false
	}

	return uid, true
}
