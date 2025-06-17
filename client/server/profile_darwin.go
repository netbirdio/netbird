//go:build darwin
// +build darwin

package server

import "path/filepath"

func getSystemProfilesDir() string {
	return "/Library/Application Support/Netbird/Profiles"
}

func getUserProfilesDir(username string) string {
	return filepath.Join("/Users", sanitazeUsername(username), "Library", "Application Support", "Netbird", "Profiles")
}
