package ipcauth

// isConsoleUser has no meaning on iOS, which has no console session to sit at.
//
// iOS satisfies the darwin constraint, so this keeps it off the macOS lookup.
// That one reaches SystemConfiguration through purego, which refuses to build
// for iOS without cgo.
func isConsoleUser(Identity) bool {
	return false
}
