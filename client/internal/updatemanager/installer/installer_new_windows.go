package installer

import (
	"os"
	"path/filepath"
)

var (
	// defaultTempDir is OS specific
	defaultTempDir = filepath.Join(os.Getenv("ProgramData"), "Netbird", "tmp-install")
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
