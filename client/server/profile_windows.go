//go:build windows
// +build windows

package server

import (
	"os"
	"path/filepath"
)

func getSystemProfilesDir() string {
	return filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird", "Profiles")
}

func getUserProfilesDir(username string) string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Netbird", "Profiles")
}
