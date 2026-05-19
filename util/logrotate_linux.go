//go:build linux

package util

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	defaultLogrotateConfPath = "/etc/logrotate.conf"
	defaultLogrotateConfDir  = "/etc/logrotate.d"
	netbirdString            = "netbird"
)

// FindLogrotateConflicts scans the standard logrotate locations for
// indications of conflict with netbird. It returns true and the config file
// path if a conflict was found.
func FindFirstLogrotateConflict() (bool, string) {
	for _, f := range listLogrotateConfigs() {
		present, err := scanLogrotateFile(f, netbirdString)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Debugf("scan %s: %v", f, err)
			}
			continue
		}
		if present {
			return present, f
		}
	}
	return false, ""
}

// listLogrotateConfigs returns all config files for logrotate.
func listLogrotateConfigs() []string {
	files := []string{defaultLogrotateConfPath}
	entries, err := os.ReadDir(defaultLogrotateConfDir)
	if err != nil {
		return files
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, filepath.Join(defaultLogrotateConfDir, e.Name()))
	}
	return files
}

// scanLogrotateFile reads a config and reports if a non-comment line
// contains the given substring.
func scanLogrotateFile(path string, substring string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Debugf("close %s: %v", path, err)
		}
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(stripLogrotateComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.Contains(line, substring) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func stripLogrotateComment(line string) string {
	before, _, _ := strings.Cut(line, "#")
	return before
}
