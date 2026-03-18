package installer

import (
	"path/filepath"
	"strings"
)

func UpdaterBinaryNameWithoutExtension() string {
	ext := filepath.Ext(updaterBinary)
	return strings.TrimSuffix(updaterBinary, ext)
}
