package server

import (
	"os"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

func checkDirOwnership(ipcauth.Identity, string, os.FileInfo) error {
	return nil
}
