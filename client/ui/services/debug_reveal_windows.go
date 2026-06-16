package services

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SW_SHOWNORMAL for ShellExecuteW's nShowCmd.
const swShowNormal = 1

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")
)

// revealFile opens Explorer focused on path. The debug bundle is written by the
// daemon (running as SYSTEM) into C:\Windows\SystemTemp, whose ACL denies the
// logged-in user. A plain "explorer /select" can't traverse it, so we elevate
// via the ShellExecuteW "runas" verb (UAC prompt) — the elevated Explorer can
// read the folder and highlight the file.
func revealFile(path string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("encode verb: %w", err)
	}
	file, err := windows.UTF16PtrFromString("explorer.exe")
	if err != nil {
		return fmt.Errorf("encode file: %w", err)
	}
	params, err := windows.UTF16PtrFromString("/select," + path)
	if err != nil {
		return fmt.Errorf("encode params: %w", err)
	}

	// ShellExecuteW returns an HINSTANCE; a value <=32 is an error code.
	ret, _, _ := procShellExecute.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		0,
		swShowNormal,
	)
	if ret <= 32 {
		// Elevation declined or failed: fall back to an unelevated reveal of the
		// parent directory so the user at least lands near the bundle.
		return exec.Command("explorer", filepath.Dir(path)).Start() //nolint:gosec
	}
	return nil
}
