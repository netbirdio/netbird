//go:build unix

// Package flock provides best-effort advisory file locking using flock(2).
//
// This is used for cross-replica coordination (e.g. preventing duplicate
// ACME requests). Note that flock(2) does NOT work reliably on NFS volumes:
// on NFSv3 it depends on the NLM daemon, on NFSv4 Linux emulates it via
// fcntl locks with different semantics. Callers must treat lock failures
// as non-fatal and proceed without the lock.
package flock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const retryInterval = 100 * time.Millisecond

// Lock acquires an exclusive advisory lock on the given file path.
// It creates the lock file if it does not exist. The lock attempt
// respects context cancellation by using non-blocking flock with polling.
// The caller must call Unlock with the returned *os.File when done.
func Lock(ctx context.Context, path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}

	timer := time.NewTimer(retryInterval)
	defer timer.Stop()

	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return f, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			if cerr := f.Close(); cerr != nil {
				log.Debugf("close lock file %s: %v", path, cerr)
			}
			return nil, fmt.Errorf("acquire lock on %s: %w", path, err)
		}

		select {
		case <-ctx.Done():
			if cerr := f.Close(); cerr != nil {
				log.Debugf("close lock file %s: %v", path, cerr)
			}
			return nil, ctx.Err()
		case <-timer.C:
			timer.Reset(retryInterval)
		}
	}
}

// Unlock releases the lock and closes the file.
func Unlock(f *os.File) error {
	if f == nil {
		return nil
	}

	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Debugf("close lock file: %v", cerr)
		}
	}()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("release lock: %w", err)
	}

	return nil
}
