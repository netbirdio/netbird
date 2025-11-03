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
func (u *Installer) RunInstallation(targetVersion string) error {
	if err := u.mkTempDir(); err != nil {
		return err
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

	log.Infof("run updater binary: %s, %s, %s", updaterPath, targetVersion, workspace)

	updateCmd := exec.Command(updaterPath, "--temp-dir", defaultTempDir, "--service-dir", workspace, "--target-version", targetVersion, "--dry-run=true")
	// todo apply it
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

func (u *Installer) mkTempDir() error {
	if err := os.MkdirAll(defaultTempDir, 0o755); err != nil {
		log.Debugf("failed to create tempdir: %s", defaultTempDir)
		return err
	}
	return nil
}

func (u *Installer) copyUpdater() (string, error) {
	dstPath := filepath.Join(u.tempDir, updaterBinary)

	uiBinary, err := u.uiBinaryFile()
	if err != nil {
		return "", err
	}

	srcFile, err := os.Open(uiBinary)
	if err != nil {
		log.Debugf("Failed to open updater binary: %v", err)
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	if err := os.Chmod(dstPath, 0755); err != nil {
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	return dstPath, nil
}

func (u *Installer) downloadFileToTemporaryDir(ctx context.Context, fileURL string) (string, error) {
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
