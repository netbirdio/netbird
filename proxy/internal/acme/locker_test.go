package acme

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlockLockerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	locker := newFlockLocker(dir, nil)

	unlock, err := locker.Lock(context.Background(), "example.com")
	require.NoError(t, err)
	require.NotNil(t, unlock)

	// Lock file should exist.
	assert.FileExists(t, filepath.Join(dir, "example.com.lock"))

	unlock()
}

func TestNoopLocker(t *testing.T) {
	locker := noopLocker{}
	unlock, err := locker.Lock(context.Background(), "example.com")
	require.NoError(t, err)
	require.NotNil(t, unlock)
	unlock()
}

func TestNewCertLockerDefaultsToFlock(t *testing.T) {
	dir := t.TempDir()

	// t.Setenv registers cleanup to restore the original value.
	// os.Unsetenv is needed because the production code uses LookupEnv,
	// which distinguishes "empty" from "not set".
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	locker := newCertLocker(CertLockAuto, dir, nil)

	_, ok := locker.(*flockLocker)
	assert.True(t, ok, "auto without k8s env should select flockLocker")
}

func TestNewCertLockerExplicitFlock(t *testing.T) {
	dir := t.TempDir()
	locker := newCertLocker(CertLockFlock, dir, nil)

	_, ok := locker.(*flockLocker)
	assert.True(t, ok, "explicit flock should select flockLocker")
}

func TestNewCertLockerK8sFallsBackToFlock(t *testing.T) {
	dir := t.TempDir()

	// k8s-lease without SA files should fall back to flock.
	locker := newCertLocker(CertLockK8sLease, dir, nil)

	_, ok := locker.(*flockLocker)
	assert.True(t, ok, "k8s-lease without SA should fall back to flockLocker")
}
