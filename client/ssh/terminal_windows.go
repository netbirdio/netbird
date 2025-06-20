//go:build windows

package ssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ConsoleUnavailableError indicates that Windows console handles are not available
// (e.g., in CI environments where stdout/stdin are redirected)
type ConsoleUnavailableError struct {
	Operation string
	Err       error
}

func (e *ConsoleUnavailableError) Error() string {
	return fmt.Sprintf("console unavailable for %s: %v", e.Operation, e.Err)
}

func (e *ConsoleUnavailableError) Unwrap() error {
	return e.Err
}

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

const (
	enableProcessedInput            = 0x0001
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableVirtualTerminalProcessing = 0x0004
	enableVirtualTerminalInput      = 0x0200
)

type coord struct {
	x, y int16
}

type smallRect struct {
	left, top, right, bottom int16
}

type consoleScreenBufferInfo struct {
	size              coord
	cursorPosition    coord
	attributes        uint16
	window            smallRect
	maximumWindowSize coord
}

func (c *Client) setupTerminalMode(_ context.Context, session *ssh.Session) error {
	if err := c.saveWindowsConsoleState(); err != nil {
		var consoleErr *ConsoleUnavailableError
		if errors.As(err, &consoleErr) {
			// Console is unavailable (e.g., CI environment), continue with defaults
			log.Debugf("console unavailable, continuing with defaults: %v", err)
			c.terminalFd = 0
		} else {
			return fmt.Errorf("save console state: %w", err)
		}
	}

	if err := c.enableWindowsVirtualTerminal(); err != nil {
		var consoleErr *ConsoleUnavailableError
		if errors.As(err, &consoleErr) {
			// Console is unavailable, this is expected in CI environments
			log.Debugf("virtual terminal unavailable: %v", err)
		} else {
			log.Debugf("failed to enable virtual terminal: %v", err)
		}
	}

	w, h := c.getWindowsConsoleSize()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
		ssh.ICRNL:         1,
		ssh.OPOST:         1,
		ssh.ONLCR:         1,
		ssh.ISIG:          1,
		ssh.ICANON:        1,
		ssh.VINTR:         3,   // Ctrl+C
		ssh.VQUIT:         28,  // Ctrl+\
		ssh.VERASE:        127, // Backspace
		ssh.VKILL:         21,  // Ctrl+U
		ssh.VEOF:          4,   // Ctrl+D
		ssh.VEOL:          0,
		ssh.VEOL2:         0,
		ssh.VSTART:        17,  // Ctrl+Q
		ssh.VSTOP:         19,  // Ctrl+S
		ssh.VSUSP:         26,  // Ctrl+Z
		ssh.VDISCARD:      15,  // Ctrl+O
		ssh.VWERASE:       23,  // Ctrl+W
		ssh.VLNEXT:        22,  // Ctrl+V
		ssh.VREPRINT:      18,  // Ctrl+R
	}

	return session.RequestPty("xterm-256color", h, w, modes)
}

func (c *Client) saveWindowsConsoleState() error {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("panic in saveWindowsConsoleState: %v", r)
		}
	}()

	stdout := syscall.Handle(os.Stdout.Fd())
	stdin := syscall.Handle(os.Stdin.Fd())

	var stdoutMode, stdinMode uint32

	ret, _, err := procGetConsoleMode.Call(uintptr(stdout), uintptr(unsafe.Pointer(&stdoutMode)))
	if ret == 0 {
		log.Debugf("failed to get stdout console mode: %v", err)
		return &ConsoleUnavailableError{
			Operation: "get stdout console mode",
			Err:       err,
		}
	}

	ret, _, err = procGetConsoleMode.Call(uintptr(stdin), uintptr(unsafe.Pointer(&stdinMode)))
	if ret == 0 {
		log.Debugf("failed to get stdin console mode: %v", err)
		return &ConsoleUnavailableError{
			Operation: "get stdin console mode",
			Err:       err,
		}
	}

	c.terminalFd = 1
	c.windowsStdoutMode = stdoutMode
	c.windowsStdinMode = stdinMode

	log.Debugf("saved Windows console state - stdout: 0x%04x, stdin: 0x%04x", stdoutMode, stdinMode)
	return nil
}

func (c *Client) enableWindowsVirtualTerminal() error {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("panic in enableWindowsVirtualTerminal: %v", r)
		}
	}()

	stdout := syscall.Handle(os.Stdout.Fd())
	stdin := syscall.Handle(os.Stdin.Fd())
	var mode uint32

	ret, _, err := procGetConsoleMode.Call(uintptr(stdout), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		log.Debugf("failed to get stdout console mode for VT setup: %v", err)
		return &ConsoleUnavailableError{
			Operation: "get stdout console mode for VT",
			Err:       err,
		}
	}

	mode |= enableVirtualTerminalProcessing
	ret, _, err = procSetConsoleMode.Call(uintptr(stdout), uintptr(mode))
	if ret == 0 {
		log.Debugf("failed to enable virtual terminal processing: %v", err)
		return &ConsoleUnavailableError{
			Operation: "enable virtual terminal processing",
			Err:       err,
		}
	}

	ret, _, err = procGetConsoleMode.Call(uintptr(stdin), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		log.Debugf("failed to get stdin console mode for VT setup: %v", err)
		return &ConsoleUnavailableError{
			Operation: "get stdin console mode for VT",
			Err:       err,
		}
	}

	mode &= ^uint32(enableLineInput | enableEchoInput | enableProcessedInput)
	mode |= enableVirtualTerminalInput
	ret, _, err = procSetConsoleMode.Call(uintptr(stdin), uintptr(mode))
	if ret == 0 {
		log.Debugf("failed to set stdin raw mode: %v", err)
		return &ConsoleUnavailableError{
			Operation: "set stdin raw mode",
			Err:       err,
		}
	}

	log.Debugf("enabled Windows virtual terminal processing")
	return nil
}

func (c *Client) getWindowsConsoleSize() (int, int) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("panic in getWindowsConsoleSize: %v", r)
		}
	}()

	stdout := syscall.Handle(os.Stdout.Fd())
	var csbi consoleScreenBufferInfo

	ret, _, err := procGetConsoleScreenBufferInfo.Call(uintptr(stdout), uintptr(unsafe.Pointer(&csbi)))
	if ret == 0 {
		log.Debugf("failed to get console buffer info, using defaults: %v", err)
		return 80, 24
	}

	width := int(csbi.window.right - csbi.window.left + 1)
	height := int(csbi.window.bottom - csbi.window.top + 1)

	log.Debugf("Windows console size: %dx%d", width, height)
	return width, height
}

func (c *Client) restoreWindowsConsoleState() {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("panic in restoreWindowsConsoleState: %v", r)
		}
	}()

	if c.terminalFd != 1 {
		return
	}

	stdout := syscall.Handle(os.Stdout.Fd())
	stdin := syscall.Handle(os.Stdin.Fd())

	ret, _, err := procSetConsoleMode.Call(uintptr(stdout), uintptr(c.windowsStdoutMode))
	if ret == 0 {
		log.Debugf("failed to restore stdout console mode: %v", err)
	}

	ret, _, err = procSetConsoleMode.Call(uintptr(stdin), uintptr(c.windowsStdinMode))
	if ret == 0 {
		log.Debugf("failed to restore stdin console mode: %v", err)
	}

	c.terminalFd = 0
	c.windowsStdoutMode = 0
	c.windowsStdinMode = 0

	log.Debugf("restored Windows console state")
}