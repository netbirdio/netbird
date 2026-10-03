//go:build !windows

package server

import (
	"errors"
	"os"
	"syscall"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

func checkDirOwnership(caller ipcauth.Identity, _ string, info os.FileInfo) error {
	if caller.UID == 0 {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine destination ownership")
	}
	if stat.Uid != caller.UID {
		return errors.New("destination is not owned by the caller")
	}
	return nil
}
