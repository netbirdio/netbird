package installer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	daemonName    = "netbird.exe"
	uiName        = "netbird-ui.exe"
	updaterBinary = "updater.exe"

	msiLogFile = "msi.log"

	// ERROR_SUCCESS_REBOOT_REQUIRED and ERROR_SUCCESS_REBOOT_INITIATED
	msiRebootRequired  = 3010
	msiRebootInitiated = 1641

	processExitWait = 10 * time.Second

	msiDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.msi"
	exeDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.exe"
)

var (
	defaultTempDir = filepath.Join(os.Getenv("ProgramData"), "Netbird", "tmp-install")

	// for the cleanup
	binaryExtensions = []string{"msi", "exe"}
)

// Setup runs the installer with appropriate arguments and manages the daemon/UI state
// This will be run by the updater process
func (u *Installer) Setup(ctx context.Context, dryRun bool, installerFile string, daemonFolder string) (resultErr error) {
	resultHandler := NewResultHandler(u.tempDir)

	var uiSessions []uint32

	// Always ensure daemon and UI are restarted after setup
	defer func() {
		log.Infof("starting daemon back")
		if err := u.startDaemon(daemonFolder); err != nil {
			log.Errorf("failed to start daemon: %v", err)
		}

		log.Infof("starting UI back")
		if err := u.startUI(daemonFolder, uiSessions); err != nil {
			log.Errorf("failed to start UI: %v", err)
		}

		log.Infof("write out result")
		var err error
		if resultErr == nil {
			err = resultHandler.WriteSuccess()
		} else {
			err = resultHandler.WriteErr(resultErr)
		}
		if err != nil {
			log.Errorf("failed to write update result: %v", err)
		}
	}()

	if dryRun {
		log.Infof("dry-run mode enabled, skipping actual installation")
		resultErr = fmt.Errorf("dry-run mode enabled")
		return
	}

	installerType, err := typeByFileExtension(installerFile)
	if err != nil {
		log.Debugf("%v", err)
		resultErr = err
		return
	}

	// The UI holds an open handle on its own image. Left running, Restart Manager
	// cannot shut it down (msiexec runs as LocalSystem here, the UI as the
	// interactive user), so the MSI falls back to replacing the file on reboot and
	// marks the install as restart-required. The deferred close-application action
	// in the package runs too late to prevent that, it happens after
	// InstallValidate has already registered the file as in use.
	uiSessions = killUI()

	var cmd *exec.Cmd
	switch installerType {
	case TypeExe:
		log.Infof("run exe installer: %s", installerFile)
		cmd = exec.CommandContext(ctx, installerFile, "/S")
	default:
		installerDir := filepath.Dir(installerFile)
		logPath := filepath.Join(installerDir, msiLogFile)
		log.Infof("run msi installer: %s", installerFile)
		// REBOOT=ReallySuppress: a silent install has no way to ask, so without it
		// msiexec reboots the machine on its own if it decides one is needed.
		cmd = exec.CommandContext(ctx, "msiexec.exe", "/i", filepath.Base(installerFile), "/qn", "/norestart", "REBOOT=ReallySuppress", "/l*v", logPath)
	}

	cmd.Dir = filepath.Dir(installerFile)

	if resultErr = cmd.Start(); resultErr != nil {
		log.Errorf("error starting installer: %v", resultErr)
		return
	}

	log.Infof("installer started with PID %d", cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		if !isRebootPending(err) {
			resultErr = err
			log.Errorf("installer process finished with error: %v", err)
			return
		}
		log.Warnf("installer completed but reported a pending reboot, some files will be replaced on the next restart")
	}

	return nil
}

func (u *Installer) startDaemon(daemonFolder string) error {
	log.Infof("starting netbird service")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, filepath.Join(daemonFolder, daemonName), "service", "start")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Debugf("failed to start netbird service: %v, output: %s", err, string(output))
		return err
	}
	log.Infof("netbird service started successfully")
	return nil
}

func (u *Installer) startUI(daemonFolder string, sessionIDs []uint32) error {
	uiPath := filepath.Join(daemonFolder, uiName)
	log.Infof("starting netbird-ui: %s", uiPath)

	if len(sessionIDs) == 0 {
		sessionID := windows.WTSGetActiveConsoleSessionId()
		if sessionID == 0xFFFFFFFF {
			return fmt.Errorf("no active user session found")
		}
		sessionIDs = []uint32{sessionID}
	}

	var errs []error
	for _, sessionID := range sessionIDs {
		if err := startUIInSession(uiPath, sessionID); err != nil {
			errs = append(errs, fmt.Errorf("session %d: %w", sessionID, err))
			continue
		}
		log.Infof("netbird-ui started successfully in session %d", sessionID)
	}
	return errors.Join(errs...)
}

// isRebootPending reports whether the installer exit code means it succeeded but
// left work for the next restart. The reboot itself is suppressed, so this is not
// a failure.
func isRebootPending(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}

	switch exitErr.ExitCode() {
	case msiRebootRequired, msiRebootInitiated:
		return true
	default:
		return false
	}
}

// killUI terminates any running netbird-ui process and returns the IDs of the
// interactive sessions the terminated processes belonged to. Setup starts the
// UI again in those sessions once the installer is done.
func killUI() []uint32 {
	pids, err := processIDsByName(uiName)
	if err != nil {
		log.Warnf("failed to look up %s processes: %v", uiName, err)
		return nil
	}

	sessions := make(map[uint32]struct{})
	for _, pid := range pids {
		var sessionID uint32
		if err := windows.ProcessIdToSessionId(pid, &sessionID); err != nil {
			log.Warnf("failed to look up session of %s (PID %d): %v", uiName, pid, err)
		}

		if err := terminateProcess(pid); err != nil {
			log.Warnf("failed to terminate %s (PID %d): %v", uiName, pid, err)
			continue
		}
		log.Infof("terminated %s (PID %d) in session %d", uiName, pid, sessionID)

		if sessionID != 0 {
			sessions[sessionID] = struct{}{}
		}
	}

	sessionIDs := make([]uint32, 0, len(sessions))
	for sessionID := range sessions {
		sessionIDs = append(sessionIDs, sessionID)
	}
	return sessionIDs
}

func processIDsByName(name string) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(snapshot); err != nil {
			log.Warnf("failed to close process snapshot: %v", err)
		}
	}()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var pids []uint32
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), name) {
			pids = append(pids, entry.ProcessID)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}

	return pids, nil
}

func terminateProcess(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		// The process may have exited between enumeration and now.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		return fmt.Errorf("open process: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			log.Warnf("failed to close process handle: %v", err)
		}
	}()

	if err := windows.TerminateProcess(handle, 0); err != nil {
		return fmt.Errorf("terminate process: %w", err)
	}

	// Wait for the handle to signal so the image file is released before the
	// installer tries to overwrite it. A timeout is reported through the returned
	// event, not through err, which stays nil unless the wait itself failed.
	event, err := windows.WaitForSingleObject(handle, uint32(processExitWait.Milliseconds()))
	if err != nil {
		return fmt.Errorf("wait for process exit: %w", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("wait for process exit: unexpected wait result %#x", event)
	}

	return nil
}

func startUIInSession(uiPath string, sessionID uint32) error {
	// Get the user token for that session
	var userToken windows.Token
	err := windows.WTSQueryUserToken(sessionID, &userToken)
	if err != nil {
		return fmt.Errorf("failed to query user token: %w", err)
	}
	defer func() {
		if err := userToken.Close(); err != nil {
			log.Warnf("failed to close user token: %v", err)
		}
	}()

	// Duplicate the token to a primary token
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		userToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return fmt.Errorf("failed to duplicate token: %w", err)
	}
	defer func() {
		if err := primaryToken.Close(); err != nil {
			log.Warnf("failed to close token: %v", err)
		}
	}()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, primaryToken, false); err != nil {
		return fmt.Errorf("create environment block: %w", err)
	}
	defer func() {
		if err := windows.DestroyEnvironmentBlock(env); err != nil {
			log.Warnf("failed to destroy environment block: %v", err)
		}
	}()

	// Prepare startup info
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = windows.StringToUTF16Ptr("winsta0\\default")

	var pi windows.ProcessInformation

	cmdLine, err := windows.UTF16PtrFromString(fmt.Sprintf("\"%s\"", uiPath))
	if err != nil {
		return fmt.Errorf("failed to convert path to UTF16: %w", err)
	}

	creationFlags := uint32(0x00000200 | 0x00000008 | 0x00000400) // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT

	err = windows.CreateProcessAsUser(
		primaryToken,
		nil,
		cmdLine,
		nil,
		nil,
		false,
		creationFlags,
		env,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcessAsUser failed: %w", err)
	}

	// Close handles
	if err := windows.CloseHandle(pi.Process); err != nil {
		log.Warnf("failed to close process handle: %v", err)
	}
	if err := windows.CloseHandle(pi.Thread); err != nil {
		log.Warnf("failed to close thread handle: %v", err)
	}

	return nil
}

func urlWithVersionArch(it Type, version string) string {
	var url string
	if it == TypeExe {
		url = exeDownloadURL
	} else {
		url = msiDownloadURL
	}
	url = strings.ReplaceAll(url, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
