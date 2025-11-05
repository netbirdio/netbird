//go:build windows || darwin

package installer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

type Installer struct {
	tempDir string
}

// New used by the service
func New() (*Installer, error) {
	return &Installer{
		tempDir: defaultTempDir,
	}, nil
}

// NewWithDir used by the updater process, get the tempDir from the service via cmd line
func NewWithDir(tempDir string) *Installer {
	return &Installer{
		tempDir: tempDir,
	}
}

// RunInstallation starts the updater process to run the installation
// This will run by the original service process
func (u *Installer) RunInstallation(ctx context.Context, targetVersion string) error {
	if err := u.mkTempDir(); err != nil {
		return err
	}

	if err := validateTargetVersion(targetVersion); err != nil {
		return err
	}

	var installerFile string
	if installerType := typeOfInstaller(ctx); installerType.Downloadable() {
		log.Infof("download installer")
		var err error
		installerFile, err = u.downloadInstaller(ctx, installerType, targetVersion)
		if err != nil {
			log.Errorf("failed to download installer: %v", err)
			return err
		}
	}

	log.Infof("running installer")
	updaterPath, err := u.copyUpdater()
	if err != nil {
		return err
	}

	// the directory where the service has been installed
	workspace, err := getServiceDir()
	if err != nil {
		return err
	}

	args := []string{
		"--temp-dir", u.tempDir,
		"--service-dir", workspace,
		"--dry-run=true",
	}

	if installerFile != "" {
		args = append(args, "--installer-file", filepath.Join(u.tempDir, installerFile))
	}

	updateCmd := exec.Command(updaterPath, args...)
	log.Infof("starting updater process: %s", updateCmd.String())
	/*
		updateCmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // 0x00000008 is DETACHED_PROCESS
		}
	*/

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

// CleanUpInstallerFiles
// - the installer file (pkg, exe, msi)
// - result.json file to prevent automatically showing the deprecated error state
// - the selfcopy updater.exe
func (u *Installer) CleanUpInstallerFiles() error {
	// Check if tempDir exists
	info, err := os.Stat(u.tempDir)
	if err != nil {
		if os.IsNotExist(err) || !info.IsDir() {
			return nil
		}
		return err
	}

	var merr *multierror.Error

	if err := os.Remove(filepath.Join(u.tempDir, updaterBinary)); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("failed to remove updater binary: %w", err))
	}

	entries, err := os.ReadDir(u.tempDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		for _, ext := range binaryExtensions {
			if strings.HasSuffix(strings.ToLower(name), strings.ToLower(ext)) {
				if err := os.Remove(filepath.Join(u.tempDir, name)); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("failed to remove %s: %w", name, err))
				}
				break
			}
		}
	}

	return nil
}

func (u *Installer) downloadInstaller(ctx context.Context, installerType Type, targetVersion string) (string, error) {
	fileURL := urlWithVersionArch(installerType, targetVersion)

	// Clean up temp directory on error
	var success bool
	defer func() {
		if !success {
			if err := os.RemoveAll(u.tempDir); err != nil {
				log.Errorf("error cleaning up temporary directory: %v", err)
			}
		}
	}()

	fileNameParts := strings.Split(fileURL, "/")
	out, err := os.Create(filepath.Join(u.tempDir, fileNameParts[len(fileNameParts)-1]))
	if err != nil {
		return "", fmt.Errorf("error creating temporary file: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Errorf("error closing temporary file: %v", err)
		}
	}()

	log.Debugf("downloading update file from %s", fileURL)
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating file download request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("error downloading update file, received status code: %d", resp.StatusCode)
		return "", fmt.Errorf("error downloading file, received status code: %d", resp.StatusCode)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}

	log.Infof("downloaded update file to %s", out.Name())

	success = true // Mark success to prevent cleanup
	return out.Name(), nil
}

func (u *Installer) TempDir() string {
	return u.tempDir
}

func (u *Installer) mkTempDir() error {
	if err := os.MkdirAll(defaultTempDir, 0o755); err != nil {
		log.Debugf("failed to create tempdir: %s", defaultTempDir)
		return err
	}
	return nil
}

func (u *Installer) copyUpdater() (string, error) {
	src, err := getServiceBinary()
	if err != nil {
		return "", fmt.Errorf("failed to get updater binary: %w", err)
	}

	dst := filepath.Join(u.tempDir, updaterBinary)
	if err := copyFile(src, dst); err != nil {
		return "", fmt.Errorf("failed to copy updater binary: %w", err)
	}

	if err := os.Chmod(dst, 0o755); err != nil {
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	return dst, nil
}

func validateTargetVersion(targetVersion string) error {
	if targetVersion == "" {
		return fmt.Errorf("target version cannot be empty")
	}

	_, err := goversion.NewVersion(targetVersion)
	if err != nil {
		return fmt.Errorf("invalid target version %q: %w", targetVersion, err)
	}

	return nil
}

func copyFile(src, dst string) error {
	log.Infof("copying %s to %s", src, dst)
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() {
		if err := in.Close(); err != nil {
			log.Warnf("failed to close source file: %v", err)
		}
	}()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Warnf("failed to close source file: %v", err)
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return nil
}

func getServiceDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exePath), nil
}

func getServiceBinary() (string, error) {
	return os.Executable()
}
