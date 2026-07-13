//go:build !windows && !darwin

package installer

import (
	"context"
	"fmt"
)

const (
	updaterBinary = "updater"
)

type Installer struct {
	tempDir string
}

// New used by the service
func New() *Installer {
	return &Installer{}
}

// NewWithDir used by the updater process, get the tempDir from the service via cmd line
func NewWithDir(tempDir string) *Installer {
	return &Installer{
		tempDir: tempDir,
	}
}

func (u *Installer) TempDir() string {
	return ""
}

func (c *Installer) LogFiles() []string {
	return []string{}
}

func (u *Installer) CleanUpInstallerFiles() error {
	return nil
}

func (u *Installer) RunInstallation(ctx context.Context, targetVersion string) error {
	return fmt.Errorf("unsupported platform")
}

// Setup runs the installer with appropriate arguments and manages the daemon/UI state
// This will be run by the updater process
func (u *Installer) Setup(ctx context.Context, dryRun bool, targetVersion string, daemonFolder string) (resultErr error) {
	return fmt.Errorf("unsupported platform")
}
