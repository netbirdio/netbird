//go:build wasm

package ipcauth

import "os"

// openForRead always fails on wasm. The Unix implementation depends on
// O_NOFOLLOW and O_NONBLOCK, which the wasm syscall packages do not define, and
// there is no local IPC on this platform for a caller to hand a path over in
// the first place. Failing closed keeps OpenOwnedFile from ever handing back a
// descriptor whose ownership could not be checked.
func openForRead(string) (*os.File, error) {
	return nil, errUnsupported
}

// fileOwnedBy always fails on wasm: there is no uid on the stat result to
// compare against the caller's identity.
func fileOwnedBy(Identity, *os.File) (bool, error) {
	return false, errUnsupported
}
