package installer

import (
	"context"
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

	// Always ensure daemon and UI are restarted after setup
	defer func() {
		log.Infof("starting daemon back")
		if err := u.startDaemon(daemonFolder); err != nil {
			log.Errorf("failed to start daemon: %v", err)
		}

		log.Infof("starting UI back")
		if err := u.startUIAsUser(daemonFolder); err != nil {
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

	var cmd *exec.Cmd
	switch installerType {
	case TypeExe:
		log.Infof("run exe installer: %s", installerFile)
		cmd = exec.CommandContext(ctx, installerFile, "/S")
	default:
		installerDir := filepath.Dir(installerFile)
		logPath := filepath.Join(installerDir, msiLogFile)
		log.Infof("run msi installer: %s", installerFile)
		cmd = exec.CommandContext(ctx, "msiexec.exe", "/i", filepath.Base(installerFile), "/quiet", "/qn", "/l*v", logPath)
	}

	cmd.Dir = filepath.Dir(installerFile)

	if resultErr = cmd.Start(); resultErr != nil {
		log.Errorf("error starting installer: %v", resultErr)
		return
	}

	log.Infof("installer started with PID %d", cmd.Process.Pid)
	if resultErr = cmd.Wait(); resultErr != nil {
		log.Errorf("installer process finished with error: %v", resultErr)
		return
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
