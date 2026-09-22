package util

import (
	"encoding/json"
	"io"
	"os"
	"syscall"
)

// readJsonShareMode reads a JSON file into res, sharing it for delete.
func readJsonShareMode(file string, res interface{}) (interface{}, error) {
	f, err := openShared(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bs, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(bs, &res); err != nil {
		return nil, err
	}

	return res, nil
}

// openShared opens file for reading and shares it for delete as well as for
// read and write.
//
// os.Open cannot: syscall.Open hardcodes FILE_SHARE_READ|FILE_SHARE_WRITE, and
// a handle that does not share delete stops a rename from replacing the file,
// which is how a write fails with "Access is denied" while somebody reads. The
// handle stays on the file it opened, so the read still sees that whole
// version while the replacement takes the name.
//
// The *os.PathError is what os returns too, so errors.Is(err, os.ErrNotExist)
// keeps working for callers that seed a file they find missing.
func openShared(file string) (*os.File, error) {
	namep, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: file, Err: err}
	}

	h, err := syscall.CreateFile(
		namep,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: file, Err: err}
	}

	return os.NewFile(uintptr(h), file), nil
}
