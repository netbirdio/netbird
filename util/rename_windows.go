package util

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileRenameInfo is FILE_RENAME_INFO in the form FileRenameInfoEx takes, where
// the leading union carries flags rather than a bare ReplaceIfExists. The name
// follows the header inline, so the struct carries room for it and
// FileNameLength says how much of that room is used.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [windows.MAX_PATH]uint16
}

// renameFile replaces newpath with oldpath, including while something holds
// newpath open for reading.
//
// os.Rename is MoveFileEx, which has to free the destination's directory entry
// there and then. A file with live handles can only be marked delete-pending,
// so that replace is refused with "Access is denied" no matter how the readers
// shared the file. POSIX semantics unlink the destination immediately and
// leave open handles reading the version they opened, which is what Unix has
// always done.
//
// Delete sharing on the readers is still the prerequisite: without it the
// rename cannot take delete access on the destination at all. See
// ReadJsonShareMode.
//
// FileRenameInfoEx wants Windows 10 1709 and a filesystem that implements it
// (FAT does not), and the inline name is bounded, so anything it will not take
// falls back to MoveFileEx. That is the behaviour callers had before, error
// included.
func renameFile(oldpath, newpath string) error {
	if err := renamePosix(oldpath, newpath); err == nil {
		return nil
	}
	return os.Rename(oldpath, newpath)
}

func renamePosix(oldpath, newpath string) error {
	// A relative destination is resolved against the handle's directory rather
	// than the working directory, which would rename to somewhere else
	// entirely. MoveFileEx resolves it the way the caller means.
	if !filepath.IsAbs(newpath) {
		return os.ErrInvalid
	}

	namep, err := windows.UTF16FromString(newpath)
	if err != nil {
		return err
	}

	var info fileRenameInfo
	if len(namep) > len(info.FileName) {
		return os.ErrInvalid
	}

	oldp, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}

	// DELETE is what renaming a file needs. Sharing it in turn keeps this
	// handle from being the one that blocks somebody else.
	h, err := windows.CreateFile(
		oldp,
		windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	// UTF16FromString terminates the name, which the byte length must not count.
	info.FileNameLength = uint32((len(namep) - 1) * 2)
	copy(info.FileName[:], namep)

	return windows.SetFileInformationByHandle(
		h,
		windows.FileRenameInfoEx,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
}
