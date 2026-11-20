package harness

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// effectiveUID and ownerUID are variables so tests can fake another owner
// without root.
var (
	effectiveUID = os.Geteuid
	ownerUID     = fileOwnerUID
)

// NotOwnerError refuses a config file the process does not own, such as a
// user's file under sudo, so setup never leaves it owned by root.
type NotOwnerError struct {
	// File is the config file setup would write.
	File string
	// Checked is File, or its nearest existing parent when File is missing.
	Checked string
	Owner   uint32
	EUID    int
}

func (e *NotOwnerError) Error() string {
	if e.Checked == e.File {
		return fmt.Sprintf("%s is owned by uid %d, not by the user running setup (uid %d): run setup as the file's owner, without sudo",
			e.File, e.Owner, e.EUID)
	}
	return fmt.Sprintf("%s does not exist and %s is owned by uid %d, not by the user running setup (uid %d): run setup as the owner of %s, without sudo",
		e.File, e.Checked, e.Owner, e.EUID, e.Checked)
}

// checkOwner refuses file, or its nearest existing parent when it is
// missing, when the effective uid does not own it. A stat error other than
// not-exist is returned, so the check never passes on an unreadable path.
func checkOwner(file string) error {
	p := file
	for {
		info, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			parent := filepath.Dir(p)
			if parent == p {
				return nil
			}
			p = parent
			continue
		}
		if err != nil {
			return fmt.Errorf("check owner of %s: %w", p, err)
		}
		uid, ok := ownerUID(info)
		if !ok {
			return nil
		}
		if euid := effectiveUID(); int64(uid) != int64(euid) {
			return &NotOwnerError{File: file, Checked: p, Owner: uid, EUID: euid}
		}
		return nil
	}
}
