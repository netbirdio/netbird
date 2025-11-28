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

func (rh *ResultHandler) GetErrorResultReason() string {
	result, err := rh.tryReadResult()
	if err == nil && !result.Success {
		return result.Error
	}

	if err := rh.cleanup(); err != nil {
		log.Warnf("failed to cleanup result file: %v", err)
	}

	return ""
}

func (rh *ResultHandler) WriteSuccess() error {
	result := Result{
		Success:    true,
		ExecutedAt: time.Now(),
	}
	return rh.write(result)
}

func (rh *ResultHandler) WriteErr(errReason error) error {
	result := Result{
		Success:    false,
		Error:      errReason.Error(),
		ExecutedAt: time.Now(),
	}
	return rh.write(result)
}

func (rh *ResultHandler) Watch(ctx context.Context) (Result, error) {
	log.Infof("start watching result: %s", rh.resultFile)

	// Check if file already exists (updater finished before we started watching)
	if result, err := rh.tryReadResult(); err == nil {
		log.Infof("installer result: %v", result)
		return result, nil
	}

	dir := filepath.Dir(rh.resultFile)

	if err := rh.waitForDirectory(ctx, dir); err != nil {
		return Result{}, err
	}

	return rh.watchForResultFile(ctx, dir)
}

func (rh *ResultHandler) waitForDirectory(ctx context.Context, dir string) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				return nil
			}
		}
	}
}

func (rh *ResultHandler) watchForResultFile(ctx context.Context, dir string) (Result, error) {
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

	if err := watcher.Add(dir); err != nil {
		return Result{}, fmt.Errorf("failed to watch directory: %v", err)
	}

	// Check again after setting up watcher to avoid race condition
	// (file could have been created between initial check and watcher setup)
	if result, err := rh.tryReadResult(); err == nil {
		log.Infof("installer result: %v", result)
		return result, nil
	}

	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return Result{}, errors.New("watcher closed unexpectedly")
			}

			if result, done := rh.handleWatchEvent(event); done {
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

func (rh *ResultHandler) handleWatchEvent(event fsnotify.Event) (Result, bool) {
	if event.Name != rh.resultFile {
		return Result{}, false
	}

	if event.Has(fsnotify.Create) {
		result, err := rh.tryReadResult()
		if err != nil {
			log.Debugf("error while reading result: %v", err)
			return result, true
		}
		log.Infof("installer result: %v", result)
		return result, true
	}

	return Result{}, false
}

// Write writes the update result to a file for the UI to read
func (rh *ResultHandler) write(result Result) error {
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
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
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

func (rh *ResultHandler) cleanup() error {
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

	if err := rh.cleanup(); err != nil {
		log.Warnf("failed to cleanup result file: %v", err)
	}

	return result, nil
}
