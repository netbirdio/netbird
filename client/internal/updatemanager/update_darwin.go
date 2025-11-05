//go:build darwin

package updatemanager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
)

const (
	pkgDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_%version_darwin_%arch.pkg"
)

func (u *UpdateManager) triggerUpdate(ctx context.Context, targetVersion string) error {
	// Use test function if set (for testing only)
	if u.updateFunc != nil {
		return u.updateFunc(ctx, targetVersion)
	}

	cmd := exec.CommandContext(ctx, "pkgutil", "--pkg-info", "io.netbird.client")
	outBytes, err := cmd.Output()
	if err != nil && cmd.ProcessState.ExitCode() == 1 {
		// Not installed using pkg file, thus installed using Homebrew

		return updateHomeBrew(ctx)
	}
	// Installed using pkg file
	path, err := downloadFileToTemporaryDir(ctx, urlWithVersionArch(targetVersion))
	if err != nil {
		return fmt.Errorf("error downloading update file: %w", err)
	}

	volume := "/"
	for _, v := range strings.Split(string(outBytes), "\n") {
		trimmed := strings.TrimSpace(v)
		if strings.HasPrefix(trimmed, "volume: ") {
			volume = strings.Split(trimmed, ": ")[1]
		}
	}

	cmd = exec.CommandContext(ctx, "installer", "-pkg", path, "-target", volume)

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error running pkg file: %w", err)
	}
	err = cmd.Process.Release()

	return err
}

func updateHomeBrew(ctx context.Context) error {
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

func urlWithVersionArch(version string) string {
	url := strings.ReplaceAll(pkgDownloadURL, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
