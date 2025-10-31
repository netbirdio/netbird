//go:build !windows

package installer

import "fmt"

type Installer struct {
	tempDir string
}

// New used by the service
func New() (*Installer, error) {
	return nil, fmt.Errorf("unsupported platform")
}

// NewWithDir used by the updater process, get the tempDir from the service via cmd line
func NewWithDir(tempDir string) *Installer {
	return &Installer{
		tempDir: tempDir,
	}
}
