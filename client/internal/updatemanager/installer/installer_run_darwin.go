package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	daemonName    = "netbird"
	updaterBinary = "updater"

	defaultTempDir = "/var/lib/netbird/tmp-install"

	pkgDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_%version_darwin_%arch.pkg"

	//updaterSrcPath = "/Applications/NetBird.app/Contents/MacOS/netbird-ui"
	updaterSrcPath = "/Users/pzoli/Desktop/NetBird.app/Contents/MacOS/netbird-ui"
)

var (
	binaryExtensions = []string{"pkg"}
)

// Setup runs the installer with appropriate arguments and manages the daemon/UI state
// This will be run by the updater process
func (u *Installer) Setup(ctx context.Context, dryRun bool, installerFile string, daemonFolder string) (resultErr error) {
	resultHandler := NewResultHandler(u.tempDir)

	// Always ensure daemon and UI are restarted after setup
	defer func() {
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

		// skip service restart if dry-run mode is enabled
		if dryRun {
			return
		}

		log.Infof("starting daemon back")
		if err := u.startDaemon(daemonFolder); err != nil {
			log.Errorf("failed to start daemon: %v", err)
		}

		// todo prevent to run UI multiple times
		log.Infof("starting UI back")
		if err := u.startUIAsUser(); err != nil {
			log.Errorf("failed to start UI: %v", err)
		}

	}()

	if dryRun {
		time.Sleep(7 * time.Second)
		log.Infof("dry-run mode enabled, skipping actual installation")
		resultErr = fmt.Errorf("dry-run mode enabled")
		return
	}

	switch typeOfInstaller(ctx) {
	case TypePKG:
		log.Infof("installing pkg file")
		if err := u.installPkgFile(ctx, installerFile); err != nil {
			resultErr = err
			break
		}
		log.Infof("pkg file installed successfully")
		return
	case TypeHomebrew:
		log.Infof("updating homebrew")
		if err := u.updateHomeBrew(ctx); err != nil {
			resultErr = err
			break
		}
		log.Infof("homebrew updated successfully")
	}

	return resultErr
}

func (u *Installer) startDaemon(daemonFolder string) error {
	log.Infof("starting netbird service")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, filepath.Join(daemonFolder, daemonName), "service", "start")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("failed to start netbird service: %v, output: %s", err, string(output))
		return err
	}
	log.Infof("netbird service started successfully")
	return nil
}

func (u *Installer) startUIAsUser() error {
	log.Infof("starting netbird-ui: %s", updaterSrcPath)

	// Get the current console user
	cmd := exec.Command("stat", "-f", "%Su", "/dev/console")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get console user: %w", err)
	}

	username := strings.TrimSpace(string(output))
	if username == "" || username == "root" {
		return fmt.Errorf("no active user session found")
	}

	log.Infof("starting UI for user: %s", username)

	// Get user's UID
	userInfo, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", username, err)
	}

	// Start the UI process as the console user using launchctl
	// This ensures the app runs in the user's context with proper GUI access
	launchCmd := exec.Command("launchctl", "asuser", userInfo.Uid, "open", "-a", updaterSrcPath)
	log.Infof("launchCmd: %s", launchCmd.String())
	// Set the user's home directory for proper macOS app behavior
	launchCmd.Env = append(os.Environ(), "HOME="+userInfo.HomeDir)

	if err := launchCmd.Start(); err != nil {
		return fmt.Errorf("failed to start UI process: %w", err)
	}

	// Release the process so it can run independently
	if err := launchCmd.Process.Release(); err != nil {
		log.Warnf("failed to release UI process: %v", err)
	}

	log.Infof("netbird-ui started successfully for user %s", username)
	return nil
}

func (u *Installer) installPkgFile(ctx context.Context, path string) error {
	volume := "/"
	for _, v := range strings.Split(path, "\n") {
		trimmed := strings.TrimSpace(v)
		if strings.HasPrefix(trimmed, "volume: ") {
			volume = strings.Split(trimmed, ": ")[1]
		}
	}

	cmd := exec.CommandContext(ctx, "installer", "-pkg", path, "-target", volume)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error running pkg file: %w", err)
	}
	res, err := cmd.CombinedOutput()
	// todo write out log result to file too
	if err != nil {
		return fmt.Errorf("error running pkg file: %w, output: %s", err, string(res))
	}
	return nil
}

func (u *Installer) updateHomeBrew(ctx context.Context) error {
	// Homebrew must be run as a non-root user
	// To find out which user installed NetBird using HomeBrew we can check the owner of our brew tap directory
	fileInfo, err := os.Stat("/opt/homebrew/Library/Taps/netbirdio/homebrew-tap/")
	if err != nil {
		return fmt.Errorf("error getting homebrew installation path info: %w", err)
	}

	fileSysInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("error checking file owner, sysInfo type is %T not *syscall.Stat_t", fileInfo.Sys())
	}

	// Get username from UID
	installer, err := user.LookupId(fmt.Sprintf("%d", fileSysInfo.Uid))
	if err != nil {
		return fmt.Errorf("error looking up brew installer user: %w", err)
	}
	userName := installer.Name
	// Get user HOME, required for brew to run correctly
	// https://github.com/Homebrew/brew/issues/15833
	homeDir := installer.HomeDir
	// Homebrew does not support installing specific versions
	// Thus it will always update to latest and ignore targetVersion
	upgradeArgs := []string{"-u", userName, "/opt/homebrew/bin/brew", "upgrade", "netbirdio/tap/netbird"}
	// Check if netbird-ui is installed
	cmd := exec.CommandContext(ctx, "brew", "info", "--json", "netbirdio/tap/netbird-ui")
	err = cmd.Run()
	if err == nil {
		// netbird-ui is installed
		upgradeArgs = append(upgradeArgs, "netbirdio/tap/netbird-ui")
	}
	cmd = exec.CommandContext(ctx, "sudo", upgradeArgs...)
	cmd.Env = append(cmd.Env, "HOME="+homeDir)

	// Homebrew upgrade doesn't restart the client on its own
	// So we have to wait for it to finish running and ensure it's done
	// And then basically restart the netbird service
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error running brew upgrade: %w", err)
	}

	currentPID := os.Getpid()

	// Restart netbird service after the fact
	// This is a workaround since attempting to restart using launchctl will kill the service and die before starting
	// the service again as it's a child process
	// using SIGTERM should ensure a clean shutdown
	process, err := os.FindProcess(currentPID)
	if err != nil {
		return fmt.Errorf("error finding current process: %w", err)
	}
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("error sending SIGTERM to current process: %w", err)
	}
	// We're dying now, which should restart us

	return nil
}

func (u *Installer) uiBinaryFile() (string, error) {
	return updaterSrcPath, nil
}

func urlWithVersionArch(_ Type, version string) string {
	url := strings.ReplaceAll(pkgDownloadURL, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
