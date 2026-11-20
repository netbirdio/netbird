//go:build unix

package harness

import (
	"io/fs"
	"syscall"
)

func fileOwnerUID(info fs.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
