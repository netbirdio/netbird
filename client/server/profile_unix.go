//go:build linux || dragonfly || freebsd || netbsd || openbsd
// +build linux dragonfly freebsd netbsd openbsd

package server

import "path/filepath"

func getSystemProfilesDir() string {
	return "/var/lib/netbird/profiles"
}

func getUserProfilesDir(username string) string {
	// ~/.config/netbird/profiles
	return filepath.Join("/home", sanitazeUsername(username), ".config", "netbird", "profiles")
}
