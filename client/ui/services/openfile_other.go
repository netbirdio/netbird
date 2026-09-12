//go:build !android && !ios && !freebsd && !js && !windows

package services

import (
	"os/exec"
	"runtime"
)

func openFile(path string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.Command(opener, path).Start()
}
