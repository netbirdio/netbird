package server

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

const (
	windowsPanicLogEnvVar = "NB_WINDOWS_PANIC_LOG"
	// STD_ERROR_HANDLE ((DWORD)-12) = 4294967284
	stdErrorHandle = ^uintptr(11)
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	// https://learn.microsoft.com/en-us/windows/console/setstdhandle
	setStdHandleFn = kernel32.NewProc("SetStdHandle")
)

func handlePanicLog() error {
	logPath := os.Getenv(windowsPanicLogEnvVar)
	if logPath == "" {
		return nil
	}

	// Ensure the directory exists
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("create panic log directory: %w", err)
	}
	if err := util.EnforcePermission(logPath); err != nil {
		return fmt.Errorf("enforce permission on panic log file: %w", err)
	}

	// Open log file with append mode
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open panic log file: %w", err)
	}

	// Redirect stderr to the file
	if err = redirectStderr(f); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			log.Warnf("failed to close file after redirect error: %v", closeErr)
		}
		return fmt.Errorf("redirect stderr: %w", err)
	}

	log.Infof("successfully configured panic logging to: %s", logPath)
	return nil
}

// redirectStderr redirects stderr to the provided file
func redirectStderr(f *os.File) error {
	// Get the current process's stderr handle
	if err := setStdHandle(f); err != nil {
		return fmt.Errorf("failed to set stderr handle: %w", err)
	}

	// Also set os.Stderr for Go's standard library
	os.Stderr = f

	return nil
}

func setStdHandle(f *os.File) error {
	handle := f.Fd()
	r0, _, e1 := setStdHandleFn.Call(stdErrorHandle, handle)
	if r0 == 0 {
		if e1 != nil {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}
