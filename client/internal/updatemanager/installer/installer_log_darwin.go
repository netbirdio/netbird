package installer

import (
	"path/filepath"
)

func (u *Installer) LogFiles() []string {
	return []string{
		filepath.Join(defaultTempDir, LogFile),
	}
}
