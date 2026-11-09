// Package wincmd locates the Windows utilities the client shells out to.
package wincmd

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// defaultSystem32Dir is where the system directory is on every supported
// install, used only when the API that reports it fails.
const defaultSystem32Dir = `C:\Windows\System32`

// System32 returns the full path of a Windows utility under the system
// directory.
//
// PATH is deliberately not consulted. The daemon runs as LocalSystem with an
// environment of its own, so whoever can place an entry in that PATH chooses
// which binary runs with those privileges. The system directory is read from
// the API rather than from %SystemRoot% for the same reason.
func System32(command string) string {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		log.Warnf("Failed to locate the Windows system directory, falling back to %s: %v", defaultSystem32Dir, err)
		sysDir = defaultSystem32Dir
	}

	return filepath.Join(sysDir, command+".exe")
}
