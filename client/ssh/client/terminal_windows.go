package client

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

const (
	enableProcessedInput            = 0x0001
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004 // Input mode: ENABLE_ECHO_INPUT
	enableVirtualTerminalProcessing = 0x0004 // Output mode: ENABLE_VIRTUAL_TERMINAL_PROCESSING (same value, different mode)
	enableVirtualTerminalInput      = 0x0200
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
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
			log.Debugf("console unavailable, not requesting PTY: %v", err)
			return nil
		}
		return fmt.Errorf("save console state: %w", err)
	}

	if err := c.enableWindowsVirtualTerminal(); err != nil {
		var consoleErr *ConsoleUnavailableError
		if errors.As(err, &consoleErr) {
			log.Debugf("virtual terminal unavailable: %v", err)
		} else {
			return fmt.Errorf("failed to enable virtual terminal: %w", err)
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
		ssh.VSTART:        17, // Ctrl+Q
		ssh.VSTOP:         19, // Ctrl+S
		ssh.VSUSP:         26, // Ctrl+Z
		ssh.VDISCARD:      15, // Ctrl+O
		ssh.VWERASE:       23, // Ctrl+W
		ssh.VLNEXT:        22, // Ctrl+V
		ssh.VREPRINT:      18, // Ctrl+R
	}

	if err := session.RequestPty("xterm-256color", h, w, modes); err != nil {
		if restoreErr := c.restoreWindowsConsoleState(); restoreErr != nil {
			log.Debugf("restore Windows console state: %v", restoreErr)
		}
		return fmt.Errorf("request pty: %w", err)
	}

	return nil
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

func (c *Client) enableWindowsVirtualTerminal() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in enableWindowsVirtualTerminal: %v", r)
		}
	}()

	stdout := syscall.Handle(os.Stdout.Fd())
	stdin := syscall.Handle(os.Stdin.Fd())
	var mode uint32

	ret, _, winErr := procGetConsoleMode.Call(uintptr(stdout), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		return &ConsoleUnavailableError{
			Operation: "get stdout console mode for VT",
			Err:       winErr,
		}
	}

	mode |= enableVirtualTerminalProcessing
	ret, _, winErr = procSetConsoleMode.Call(uintptr(stdout), uintptr(mode))
	if ret == 0 {
		return &ConsoleUnavailableError{
			Operation: "enable virtual terminal processing",
			Err:       winErr,
		}
	}

	ret, _, winErr = procGetConsoleMode.Call(uintptr(stdin), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		return &ConsoleUnavailableError{
			Operation: "get stdin console mode for VT",
			Err:       winErr,
		}
	}

	mode &= ^uint32(enableLineInput | enableEchoInput | enableProcessedInput)
	mode |= enableVirtualTerminalInput
	ret, _, winErr = procSetConsoleMode.Call(uintptr(stdin), uintptr(mode))
	if ret == 0 {
		return &ConsoleUnavailableError{
			Operation: "set stdin raw mode",
			Err:       winErr,
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

func (c *Client) restoreWindowsConsoleState() error {
	var err error
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in restoreWindowsConsoleState: %v", r)
		}
	}()

	if c.terminalFd != 1 {
		return nil
	}

	stdout := syscall.Handle(os.Stdout.Fd())
	stdin := syscall.Handle(os.Stdin.Fd())

	ret, _, winErr := procSetConsoleMode.Call(uintptr(stdout), uintptr(c.windowsStdoutMode))
	if ret == 0 {
		log.Debugf("failed to restore stdout console mode: %v", winErr)
		if err == nil {
			err = fmt.Errorf("restore stdout console mode: %w", winErr)
		}
	}

	ret, _, winErr = procSetConsoleMode.Call(uintptr(stdin), uintptr(c.windowsStdinMode))
	if ret == 0 {
		log.Debugf("failed to restore stdin console mode: %v", winErr)
		if err == nil {
			err = fmt.Errorf("restore stdin console mode: %w", winErr)
		}
	}

	c.terminalFd = 0
	c.windowsStdoutMode = 0
	c.windowsStdinMode = 0

	log.Debugf("restored Windows console state")
	return err
}
