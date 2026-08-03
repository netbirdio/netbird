//go:build windows

package ipcauth

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openForRead opens a caller-supplied path without following a reparse point at
// it. FILE_FLAG_OPEN_REPARSE_POINT is the Windows analogue of O_NOFOLLOW: it
// opens a symlink/junction itself rather than its target, so the regular-file
// check in checkOwnership refuses a link the caller planted to redirect the
// read. FILE_FLAG_BACKUP_SEMANTICS lets a directory open too (as os.Open does),
// so a directory planted at the path is refused as non-regular rather than
// erroring here. The share mode matches os.Open so a log being written stays
// openable.
func openForRead(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("convert path %s: %w", path, err)
	}

	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	return os.NewFile(uintptr(handle), path), nil
}

// fileOwnedBy compares the file's owner SID with the caller's. Files an elevated
// process creates are owned by BUILTIN\Administrators rather than by the user,
// but such a caller is privileged and never reaches this check.
func fileOwnedBy(id Identity, f *os.File) (bool, error) {
	// x/sys/windows GetSecurityInfo frees the OS buffer itself and returns a
	// Go-heap copy, so there is nothing to LocalFree here.
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read security info: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return false, fmt.Errorf("read owner: %w", err)
	}

	return id.SID != "" && owner.String() == id.SID, nil
}
