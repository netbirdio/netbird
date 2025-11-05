package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

const (
	resultFile = "result.json"
)

type Result struct {
	Success    bool
	Error      string
	ExecutedAt time.Time
}

// ResultHandler handles reading and writing update results
type ResultHandler struct {
	resultFile string
}

// NewResultHandler creates a new communicator with the given directory path
// The result file will be created as "result.json" in the specified directory
func NewResultHandler(installerDir string) *ResultHandler {
	// Create it if it doesn't exist
	// do not care if already exists
	_ = os.MkdirAll(installerDir, 0o700)

	rh := &ResultHandler{
		resultFile: filepath.Join(installerDir, resultFile),
	}
	return rh
}

func (rh *ResultHandler) Watch(ctx context.Context) (Result, error) {
	log.Infof("start watching result: %s", rh.resultFile)

	defer func() {
		if err := rh.Cleanup(); err != nil {
			log.Warnf("failed to cleanup result file: %v", err)
		}
	}()

	// Check if file already exists (updater finished before we started watching)
	if result, err := rh.tryReadResult(); err == nil {
		log.Infof("installer result: %v", result)
		return result, nil
	}

	dir := filepath.Dir(rh.resultFile)

	// Wait for directory to exist (with timeout from context)
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

DirectoryReady:
	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-ticker.C:
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				// Directory exists, continue with watcher setup
				break DirectoryReady
			}
		}
	}

	// Create filesystem watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error(err)
		return Result{}, err
	}

	defer func() {
		if err := watcher.Close(); err != nil {
			log.Warnf("failed to close watcher: %v", err)
		}
	}()

	// Watch the directory (not the file, since it doesn't exist yet)
	if err := watcher.Add(dir); err != nil {
		return Result{}, fmt.Errorf("failed to watch directory: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return Result{}, errors.New("watcher closed unexpectedly")
			}

			// Check if this is our result file
			if event.Name != rh.resultFile {
				continue
			}

			if event.Has(fsnotify.Create) {
				result, err := rh.tryReadResult()
				if err != nil {
					log.Debugf("error while reading result: %v", err)
					return result, err
				}
				log.Infof("installer result: %v", result)
				return result, nil
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return Result{}, errors.New("watcher closed unexpectedly")
			}
			return Result{}, fmt.Errorf("watcher error: %w", err)
		}
	}
}

// Write writes the update result to a file for the UI to read
func (rh *ResultHandler) Write(result Result) error {
	log.Infof("write out installer result to: %s", rh.resultFile)
	// Ensure directory exists
	dir := filepath.Dir(rh.resultFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Errorf("failed to create directory %s: %v", dir, err)
		return err
	}

	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	// Write to a temporary file first, then rename for atomic operation
	tmpPath := rh.resultFile + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		log.Errorf("failed to create temp file: %s", err)
		return err
	}

	// Atomic rename
	if err := os.Rename(tmpPath, rh.resultFile); err != nil {
		if cleanupErr := os.Remove(tmpPath); cleanupErr != nil {
			log.Warnf("Failed to remove temp result file: %v", err)
		}
		return err
	}

	return nil
}

// Cleanup removes the result file if it exists
func (rh *ResultHandler) Cleanup() error {
	err := os.Remove(rh.resultFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	log.Debugf("delete installer result file: %s", rh.resultFile)
	return nil
}

// tryReadResult attempts to read and validate the result file
func (rh *ResultHandler) tryReadResult() (Result, error) {
	data, err := os.ReadFile(rh.resultFile)
	if err != nil {
		return Result{}, err
	}

	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return Result{}, fmt.Errorf("invalid result format: %w", err)
	}

	return result, nil
}
