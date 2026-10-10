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
	uiBinary      = "/Applications/NetBird.app"

	defaultTempDir = "/var/lib/netbird/tmp-install"

	pkgDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_%version_darwin_%arch.pkg"
)

var (
	binaryExtensions = []string{"pkg"}
)

// Setup runs the installer with appropriate arguments and manages the daemon/UI state
// This will be run by the updater process
func (u *Installer) Setup(ctx context.Context, dryRun bool, installerFile string, daemonFolder string) (resultErr error) {
	resultHandler := NewResultHandler(u.tempDir)
	uiWasRunning := u.isUIRunning()

	// Restart the daemon after setup. Restore the UI only when it was running
	// before the update, so a user-initiated quit is not undone by the updater.
	defer func() {
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

		// skip service restart if dry-run mode is enabled
		if dryRun {
			return
		}

		log.Infof("starting daemon back")
		if err := u.startDaemon(daemonFolder); err != nil {
			log.Errorf("failed to start daemon: %v", err)
		}

		if uiWasRunning {
			log.Infof("starting UI back")
			if err := u.startUIAsUser(); err != nil {
				log.Errorf("failed to start UI: %v", err)
			}
		} else {
			log.Infof("UI was not running before update, leaving it stopped")
		}

	}()

	if dryRun {
		time.Sleep(7 * time.Second)
		log.Infof("dry-run mode enabled, skipping actual installation")
		resultErr = fmt.Errorf("dry-run mode enabled")
		return
	}

	switch TypeOfInstaller(ctx) {
	case TypePKG:
		resultErr = u.installPkgFile(ctx, installerFile)
	case TypeHomebrew:
		resultErr = u.updateHomeBrew(ctx)
	}

	return resultErr
}

func (u *Installer) isUIRunning() bool {
	err := exec.Command("pgrep", "-x", "netbird-ui").Run()
	return err == nil
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
	log.Infof("starting netbird-ui: %s", uiBinary)

	username, err := consoleUser()
	if err != nil {
		return err
	}

	userInfo, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", username, err)
	}

	log.Infof("starting UI for user: %s (uid %s)", username, userInfo.Uid)

	launchCmd := exec.Command("launchctl", "asuser", userInfo.Uid, "sudo", "-u", username, "-H", "open", "-a", uiBinary)
	log.Infof("launchCmd: %s", launchCmd.String())

	if err := launchCmd.Run(); err != nil {
		return fmt.Errorf("run UI launch: %w", err)
	}

	log.Infof("netbird-ui started successfully for user %s", username)
	return nil
}

func consoleUser() (string, error) {
	output, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return "", fmt.Errorf("get console user: %w", err)
	}

	username := strings.TrimSpace(string(output))
	switch username {
	case "", "root", "loginwindow", "_mbsetupuser":
		return "", fmt.Errorf("no active GUI user session, console user: %q", username)
	}

	return username, nil
}

func (u *Installer) installPkgFile(ctx context.Context, path string) error {
	log.Infof("installing pkg file: %s", path)

	// Kill any existing UI processes before installation
	// This ensures the postinstall script's "open $APP" will start the new version
	u.killUI()

	volume := "/"

	cmd := exec.CommandContext(ctx, "installer", "-pkg", path, "-target", volume)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error running pkg file: %w", err)
	}
	log.Infof("installer started with PID %d", cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("error running pkg file: %w", err)
	}
	log.Infof("pkg file installed successfully")
	return nil
}

func (u *Installer) updateHomeBrew(ctx context.Context) error {
	log.Infof("updating homebrew")

	// Kill any existing UI processes before upgrade
	// This ensures the new version will be started after upgrade
	u.killUI()

	// Homebrew must be run as a non-root user
	// To find out which user installed NetBird using HomeBrew we can check the owner of our brew tap directory
	// Check both Apple Silicon and Intel Mac paths
	brewTapPath := "/opt/homebrew/Library/Taps/netbirdio/homebrew-tap/"
	brewBinPath := "/opt/homebrew/bin/brew"
	if _, err := os.Stat(brewTapPath); os.IsNotExist(err) {
		// Try Intel Mac path
		brewTapPath = "/usr/local/Homebrew/Library/Taps/netbirdio/homebrew-tap/"
		brewBinPath = "/usr/local/bin/brew"
	}

	fileInfo, err := os.Stat(brewTapPath)
	if err != nil {
		return fmt.Errorf("error getting homebrew installation path info: %w", err)
	}

	fileSysInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("error checking file owner, sysInfo type is %T not *syscall.Stat_t", fileInfo.Sys())
	}

	// Get username from UID
	brewUser, err := user.LookupId(fmt.Sprintf("%d", fileSysInfo.Uid))
	if err != nil {
		return fmt.Errorf("error looking up brew installer user: %w", err)
	}
	userName := brewUser.Username
	// Get user HOME, required for brew to run correctly
	// https://github.com/Homebrew/brew/issues/15833
	homeDir := brewUser.HomeDir

	// Check if netbird-ui is installed (must run as the brew user, not root)
	checkUICmd := exec.CommandContext(ctx, "sudo", "-u", userName, brewBinPath, "list", "--formula", "netbirdio/tap/netbird-ui")
	checkUICmd.Env = append(os.Environ(), "HOME="+homeDir)
	uiInstalled := checkUICmd.Run() == nil

	// Homebrew does not support installing specific versions
	// Thus it will always update to latest and ignore targetVersion
	upgradeArgs := []string{"-u", userName, brewBinPath, "upgrade", "netbirdio/tap/netbird"}
	if uiInstalled {
		upgradeArgs = append(upgradeArgs, "netbirdio/tap/netbird-ui")
	}

	cmd := exec.CommandContext(ctx, "sudo", upgradeArgs...)
	cmd.Env = append(os.Environ(), "HOME="+homeDir)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error running brew upgrade: %w, output: %s", err, string(output))
	}

	log.Infof("homebrew updated successfully")
	return nil
}

func (u *Installer) killUI() {
	log.Infof("killing existing netbird-ui processes")
	cmd := exec.Command("pkill", "-x", "netbird-ui")
	if output, err := cmd.CombinedOutput(); err != nil {
		// pkill returns exit code 1 if no processes matched, which is fine
		log.Debugf("pkill netbird-ui result: %v, output: %s", err, string(output))
	} else {
		log.Infof("netbird-ui processes killed")
	}
}

func urlWithVersionArch(_ Type, version string) string {
	url := strings.ReplaceAll(pkgDownloadURL, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
