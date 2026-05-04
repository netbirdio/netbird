//go:build windows

package winpty

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	ErrEmptyEnvironment = errors.New("empty environment")
)

const (
	extendedStartupInfoPresent       = 0x00080000
	createUnicodeEnvironment         = 0x00000400
	procThreadAttributePseudoConsole = 0x00020016

	PowerShellCommandFlag = "-Command"

	errCloseInputRead     = "close input read handle: %v"
	errCloseConPtyCleanup = "close ConPty handle during cleanup"
)

// PtyConfig holds configuration for Pty execution.
type PtyConfig struct {
	Shell      string
	Command    string
	Width      int
	Height     int
	WorkingDir string
}

// UserConfig holds user execution configuration.
type UserConfig struct {
	Token       windows.Handle
	Environment []string
}

var (
	kernel32                              = windows.NewLazySystemDLL("kernel32.dll")
	procClosePseudoConsole                = kernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = kernel32.NewProc("DeleteProcThreadAttributeList")
)

// ExecutePtyWithUserToken executes a command with ConPty using user token.
func ExecutePtyWithUserToken(session ssh.Session, ptyConfig PtyConfig, userConfig UserConfig) error {
	args := buildShellArgs(ptyConfig.Shell, ptyConfig.Command)
	commandLine := buildCommandLine(args)

	config := ExecutionConfig{
		Pty:     ptyConfig,
		User:    userConfig,
		Session: session,
		Context: session.Context(),
	}

	return executeConPtyWithConfig(commandLine, config)
}

// ExecutionConfig holds all execution configuration.
type ExecutionConfig struct {
	Pty     PtyConfig
	User    UserConfig
	Session ssh.Session
	Context context.Context
}

// executeConPtyWithConfig creates ConPty and executes process with configuration.
func executeConPtyWithConfig(commandLine string, config ExecutionConfig) error {
	ctx := config.Context
	session := config.Session
	width := config.Pty.Width
	height := config.Pty.Height
	userToken := config.User.Token
	userEnv := config.User.Environment
	workingDir := config.Pty.WorkingDir

	inputRead, inputWrite, outputRead, outputWrite, err := createConPtyPipes()
	if err != nil {
		return fmt.Errorf("create ConPty pipes: %w", err)
	}

	hPty, err := createConPty(width, height, inputRead, outputWrite)
	if err != nil {
		return fmt.Errorf("create ConPty: %w", err)
	}

	primaryToken, err := duplicateToPrimaryToken(userToken)
	if err != nil {
		if closeErr, _, _ := procClosePseudoConsole.Call(uintptr(hPty)); closeErr == 0 {
			log.Debugf(errCloseConPtyCleanup)
		}
		closeHandles(inputRead, inputWrite, outputRead, outputWrite)
		return fmt.Errorf("duplicate to primary token: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(primaryToken); err != nil {
			log.Debugf("close primary token: %v", err)
		}
	}()

	siEx, err := setupConPtyStartupInfo(hPty)
	if err != nil {
		if closeErr, _, _ := procClosePseudoConsole.Call(uintptr(hPty)); closeErr == 0 {
			log.Debugf(errCloseConPtyCleanup)
		}
		closeHandles(inputRead, inputWrite, outputRead, outputWrite)
		return fmt.Errorf("setup startup info: %w", err)
	}
	defer func() {
		_, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(siEx.ProcThreadAttributeList)))
	}()

	pi, err := createConPtyProcess(commandLine, primaryToken, userEnv, workingDir, siEx)
	if err != nil {
		if closeErr, _, _ := procClosePseudoConsole.Call(uintptr(hPty)); closeErr == 0 {
			log.Debugf(errCloseConPtyCleanup)
		}
		closeHandles(inputRead, inputWrite, outputRead, outputWrite)
		return fmt.Errorf("create process as user with ConPty: %w", err)
	}
	defer closeProcessInfo(pi)

	if err := windows.CloseHandle(inputRead); err != nil {
		log.Debugf(errCloseInputRead, err)
	}
	if err := windows.CloseHandle(outputWrite); err != nil {
		log.Debugf("close output write handle: %v", err)
	}

	return bridgeConPtyIO(ctx, hPty, inputWrite, outputRead, session, session, session, pi.Process)
}

// createConPtyPipes creates input/output pipes for ConPty.
func createConPtyPipes() (inputRead, inputWrite, outputRead, outputWrite windows.Handle, err error) {
	if err := windows.CreatePipe(&inputRead, &inputWrite, nil, 0); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("create input pipe: %w", err)
	}

	if err := windows.CreatePipe(&outputRead, &outputWrite, nil, 0); err != nil {
		if closeErr := windows.CloseHandle(inputRead); closeErr != nil {
			log.Debugf(errCloseInputRead, closeErr)
		}
		if closeErr := windows.CloseHandle(inputWrite); closeErr != nil {
			log.Debugf("close input write handle: %v", closeErr)
		}
		return 0, 0, 0, 0, fmt.Errorf("create output pipe: %w", err)
	}

	return inputRead, inputWrite, outputRead, outputWrite, nil
}

// createConPty creates a Windows ConPty with the specified size and pipe handles.
func createConPty(width, height int, inputRead, outputWrite windows.Handle) (windows.Handle, error) {
	size := windows.Coord{X: int16(width), Y: int16(height)}

	var hPty windows.Handle
	if err := windows.CreatePseudoConsole(size, inputRead, outputWrite, 0, &hPty); err != nil {
		return 0, fmt.Errorf("CreatePseudoConsole: %w", err)
	}

	return hPty, nil
}

// setupConPtyStartupInfo prepares the STARTUPINFOEX with ConPty attributes.
func setupConPtyStartupInfo(hPty windows.Handle) (*windows.StartupInfoEx, error) {
	var siEx windows.StartupInfoEx
	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))

	var attrListSize uintptr
	ret, _, _ := procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	if ret == 0 && attrListSize == 0 {
		return nil, fmt.Errorf("get attribute list size")
	}

	attrListBytes := make([]byte, attrListSize)
	siEx.ProcThreadAttributeList = (*windows.ProcThreadAttributeList)(unsafe.Pointer(&attrListBytes[0]))

	ret, _, err := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(siEx.ProcThreadAttributeList)),
		1,
		0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("initialize attribute list: %w", err)
	}

	ret, _, err = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(siEx.ProcThreadAttributeList)),
		0,
		procThreadAttributePseudoConsole,
		uintptr(hPty),
		unsafe.Sizeof(hPty),
		0,
		0,
	)
	if ret == 0 {
		return nil, fmt.Errorf("update thread attribute: %w", err)
	}

	return &siEx, nil
}

// createConPtyProcess creates the actual process with ConPty.
func createConPtyProcess(commandLine string, userToken windows.Handle, userEnv []string, workingDir string, siEx *windows.StartupInfoEx) (*windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	creationFlags := uint32(extendedStartupInfoPresent | createUnicodeEnvironment)

	commandLinePtr, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return nil, fmt.Errorf("convert command line to UTF16: %w", err)
	}

	envPtr, err := convertEnvironmentToUTF16(userEnv)
	if err != nil {
		return nil, err
	}

	var workingDirPtr *uint16
	if workingDir != "" {
		workingDirPtr, err = windows.UTF16PtrFromString(workingDir)
		if err != nil {
			return nil, fmt.Errorf("convert working directory to UTF16: %w", err)
		}
	}

	siEx.StartupInfo.Flags |= windows.STARTF_USESTDHANDLES
	siEx.StartupInfo.StdInput = windows.Handle(0)
	siEx.StartupInfo.StdOutput = windows.Handle(0)
	siEx.StartupInfo.StdErr = siEx.StartupInfo.StdOutput

	if userToken != windows.InvalidHandle {
		err = windows.CreateProcessAsUser(
			windows.Token(userToken),
			nil,
			commandLinePtr,
			nil,
			nil,
			true,
			creationFlags,
			envPtr,
			workingDirPtr,
			&siEx.StartupInfo,
			&pi,
		)
	} else {
		err = windows.CreateProcess(
			nil,
			commandLinePtr,
			nil,
			nil,
			true,
			creationFlags,
			envPtr,
			workingDirPtr,
			&siEx.StartupInfo,
			&pi,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("create process: %w", err)
	}

	return &pi, nil
}

// convertEnvironmentToUTF16 converts environment variables to Windows UTF16 format.
func convertEnvironmentToUTF16(userEnv []string) (*uint16, error) {
	if len(userEnv) == 0 {
		// Return nil pointer for empty environment - Windows API will inherit parent environment
		return nil, nil //nolint:nilnil // Intentional nil,nil for empty environment
	}

	var envUTF16 []uint16
	for _, envVar := range userEnv {
		if envVar != "" {
			utf16Str, err := windows.UTF16FromString(envVar)
			if err != nil {
				log.Debugf("skipping invalid environment variable: %s (error: %v)", envVar, err)
				continue
			}
			envUTF16 = append(envUTF16, utf16Str[:len(utf16Str)-1]...)
			envUTF16 = append(envUTF16, 0)
		}
	}
	envUTF16 = append(envUTF16, 0)

	if len(envUTF16) > 0 {
		return &envUTF16[0], nil
	}
	// Return nil pointer when no valid environment variables found
	return nil, nil //nolint:nilnil // Intentional nil,nil for empty environment
}

// duplicateToPrimaryToken converts an impersonation token to a primary token.
func duplicateToPrimaryToken(token windows.Handle) (windows.Handle, error) {
	var primaryToken windows.Handle
	if err := windows.DuplicateTokenEx(
		windows.Token(token),
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		(*windows.Token)(&primaryToken),
	); err != nil {
		return 0, fmt.Errorf("duplicate token: %w", err)
	}
	return primaryToken, nil
}

// SessionExiter provides the Exit method for reporting process exit status.
type SessionExiter interface {
	Exit(code int) error
}

// bridgeConPtyIO handles I/O bridging between ConPty and readers/writers.
func bridgeConPtyIO(ctx context.Context, hPty, inputWrite, outputRead windows.Handle, reader io.ReadCloser, writer io.Writer, session SessionExiter, process windows.Handle) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	startIOBridging(ctx, &wg, inputWrite, outputRead, reader, writer)

	processErr := waitForProcess(ctx, process)
	if processErr != nil {
		return processErr
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(process, &exitCode); err != nil {
		log.Debugf("get exit code: %v", err)
	} else {
		if err := session.Exit(int(exitCode)); err != nil {
			log.Debugf("report exit code: %v", err)
		}
	}

	// Clean up in the original order after process completes
	if err := reader.Close(); err != nil {
		log.Debugf("close reader: %v", err)
	}

	ret, _, err := procClosePseudoConsole.Call(uintptr(hPty))
	if ret == 0 {
		log.Debugf("close ConPty handle: %v", err)
	}

	wg.Wait()

	if err := windows.CloseHandle(outputRead); err != nil {
		log.Debugf("close output read handle: %v", err)
	}

	return nil
}

// startIOBridging starts the I/O bridging goroutines.
func startIOBridging(ctx context.Context, wg *sync.WaitGroup, inputWrite, outputRead windows.Handle, reader io.ReadCloser, writer io.Writer) {
	wg.Add(2)

	// Input: reader (SSH session) -> inputWrite (ConPty)
	go func() {
		defer wg.Done()
		defer func() {
			if err := windows.CloseHandle(inputWrite); err != nil {
				log.Debugf("close input write handle in goroutine: %v", err)
			}
		}()

		if _, err := io.Copy(&windowsHandleWriter{handle: inputWrite}, reader); err != nil {
			log.Debugf("input copy ended with error: %v", err)
		}
	}()

	// Output: outputRead (ConPty) -> writer (SSH session)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(writer, &windowsHandleReader{handle: outputRead}); err != nil {
			log.Debugf("output copy ended with error: %v", err)
		}
	}()
}

// waitForProcess waits for process completion with context cancellation.
func waitForProcess(ctx context.Context, process windows.Handle) error {
	if _, err := windows.WaitForSingleObject(process, windows.INFINITE); err != nil {
		return fmt.Errorf("wait for process %d: %w", process, err)
	}
	return nil
}

// buildShellArgs builds shell arguments for ConPty execution.
func buildShellArgs(shell, command string) []string {
	if command != "" {
		return []string{shell, PowerShellCommandFlag, command}
	}
	return []string{shell}
}

// buildCommandLine builds a Windows command line from arguments using proper escaping.
func buildCommandLine(args []string) string {
	if len(args) == 0 {
		return ""
	}

	var result strings.Builder
	for i, arg := range args {
		if i > 0 {
			result.WriteString(" ")
		}
		result.WriteString(syscall.EscapeArg(arg))
	}
	return result.String()
}

// closeHandles closes multiple Windows handles.
func closeHandles(handles ...windows.Handle) {
	for _, handle := range handles {
		if handle != windows.InvalidHandle {
			if err := windows.CloseHandle(handle); err != nil {
				log.Debugf("close handle: %v", err)
			}
		}
	}
}

// closeProcessInfo closes process and thread handles.
func closeProcessInfo(pi *windows.ProcessInformation) {
	if pi != nil {
		if err := windows.CloseHandle(pi.Process); err != nil {
			log.Debugf("close process handle: %v", err)
		}
		if err := windows.CloseHandle(pi.Thread); err != nil {
			log.Debugf("close thread handle: %v", err)
		}
	}
}

// windowsHandleReader wraps a Windows handle for reading.
type windowsHandleReader struct {
	handle windows.Handle
}

func (r *windowsHandleReader) Read(p []byte) (n int, err error) {
	var bytesRead uint32
	if err := windows.ReadFile(r.handle, p, &bytesRead, nil); err != nil {
		return 0, err
	}
	return int(bytesRead), nil
}

func (r *windowsHandleReader) Close() error {
	return windows.CloseHandle(r.handle)
}

// windowsHandleWriter wraps a Windows handle for writing.
type windowsHandleWriter struct {
	handle windows.Handle
}

func (w *windowsHandleWriter) Write(p []byte) (n int, err error) {
	var bytesWritten uint32
	if err := windows.WriteFile(w.handle, p, &bytesWritten, nil); err != nil {
		return 0, err
	}
	return int(bytesWritten), nil
}

func (w *windowsHandleWriter) Close() error {
	return windows.CloseHandle(w.handle)
}
