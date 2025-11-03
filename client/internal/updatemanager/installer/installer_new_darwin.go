package installer

import "os"

var (
	// defaultTempDir is OS specific
	defaultTempDir = "/var/lib/netbird/tmp-install"
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

func (u *Installer) MakeTempDir() (string, error) {
	if err := os.MkdirAll(u.tempDir, 0o755); err != nil {
		return "", err
	}
	return u.tempDir, nil
}
