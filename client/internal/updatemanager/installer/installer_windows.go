package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	// defaultTempDir is OS specific
	defaultTempDir = filepath.Join(os.Getenv("ProgramData"), "Netbird", "tmp-install")
)

func TempDir() string {
	return defaultTempDir
}

type Installer struct {
	tempDir string
}

// New used by the service
func New() *Installer {
	return &Installer{
		tempDir: defaultTempDir,
	}
}

// NewWithDir used by the updater process, get the tempDir from the service via cmd line
func NewWithDir(tempDir string) *Installer {
	return &Installer{
		tempDir: tempDir,
	}
}

func (u *Installer) MakeTempDir() (string, error) {
	if err := os.MkdirAll(u.tempDir, 0o755); err != nil {
		return "", err
	}
	return u.tempDir, nil
}

// RunInstallation starts the updater process to run the installation
// This will run by the original service process
func (u *Installer) RunInstallation(installerFile string) error {
	// copy the current binary to a temp location as an updater binary
	updaterPath, err := u.copyUpdater()
	if err != nil {
		return err
	}

	// the directory where the service has been installed
	workspace, err := getServiceDir()
	if err != nil {
		return err
	}

	log.Infof("run updater binary: %s", updaterPath)

	installerFullPath := filepath.Join(u.tempDir, installerFile)

	updateCmd := exec.Command(updaterPath, "--installer-path", installerFullPath, "--service-dir", workspace, "--dry-run=true")
	updateCmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // 0x00000008 is DETACHED_PROCESS
	}

	// Start the updater process asynchronously
	if err := updateCmd.Start(); err != nil {
		return err
	}

	// Release the process so the OS can fully detach it
	if err := updateCmd.Process.Release(); err != nil {
		log.Warnf("failed to release updater process: %v", err)
	}

	log.Infof("updater started with PID %d", updateCmd.Process.Pid)
	return nil
}

// Setup runs the installer with appropriate arguments and manages the daemon/UI state
// This will be run by the updater process
func (u *Installer) Setup(ctx context.Context, dryRun bool, installerPath string, daemonFolder string) (resultErr error) {
	installerFolder := filepath.Dir(installerPath)
	resultHandler := NewResultHandler(installerFolder)
	it, err := TypeByFileExtension(installerPath)
	if err != nil {
		return err
	}

	// Always ensure daemon and UI are restarted after setup
	defer func() {
		log.Infof("starting daemon back")
		if err := u.startDaemon(daemonFolder); err != nil {
			log.Errorf("failed to start daemon: %v", err)
		}

		// todo prevent to run UI multiple times
		log.Infof("starting UI back")
		if err := u.startUIAsUser(daemonFolder); err != nil {
			log.Errorf("failed to start UI: %v", err)
		}

		result := Result{
			Success:    resultErr == nil,
			ExecutedAt: time.Now(),
		}
		if resultErr != nil {
			result.Error = resultErr.Error()
		}
		log.Infof("write out result")
		if err := resultHandler.Write(result); err != nil {
			log.Errorf("failed to write update result: %v", err)
		}
	}()

	if dryRun {
		log.Infof("dry-run mode enabled, skipping actual installation")
		resultErr = fmt.Errorf("dry-run mode enabled")
		return
	}

	var cmd *exec.Cmd
	if it == TypeExe {
		log.Infof("run exe installer: %s", installerPath)
		cmd = exec.CommandContext(ctx, installerPath, "/S")
	} else {
		installerDir := filepath.Dir(installerPath)
		logPath := filepath.Join(installerDir, "msi.log")
		log.Infof("run msi installer: %s", installerPath)
		cmd = exec.CommandContext(ctx, "msiexec.exe", "/i", filepath.Base(installerPath), "/quiet", "/qn", "/l*v", logPath)
	}

	cmd.Dir = filepath.Dir(installerPath)

	if err := cmd.Start(); err != nil {
		log.Errorf("error starting installer: %v", err)
		return err
	}

	log.Infof("installer started with PID %d", cmd.Process.Pid)
	if resultErr = cmd.Wait(); resultErr != nil {
		log.Errorf("installer process finished with error: %v", resultErr)
		return
	}

	return nil
}

func (u *Installer) TempDir() string {
	return u.tempDir
}

func (u *Installer) CleanUpInstallerFile() error {
	// todo implement me
	return nil
}

func (u *Installer) cleanUpLogs() {

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

func (u *Installer) startUIAsUser(daemonFolder string) error {
	uiPath := filepath.Join(daemonFolder, uiName)
	log.Infof("starting netbird-ui: %s", uiPath)

	// Get the active console session ID
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		return fmt.Errorf("no active user session found")
	}

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

	// Prepare startup info
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = windows.StringToUTF16Ptr("winsta0\\default")

	var pi windows.ProcessInformation

	cmdLine, err := windows.UTF16PtrFromString(uiPath)
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
		nil,
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

	log.Infof("netbird-ui started successfully in session %d", sessionID)
	return nil
}

func (u *Installer) copyUpdater() (string, error) {
	if err := os.MkdirAll(u.tempDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Destination path for the copied executable
	dstPath := filepath.Join(u.tempDir, updaterBinary)

	// Open the source executable
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	srcFile, err := os.Open(execPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Create the destination file
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// Copy contents
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	// Make executable
	if err := os.Chmod(dstPath, 0755); err != nil {
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	return dstPath, nil
}

func getServiceDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exePath), nil
}
