package acme

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// TestFlockLockerSerializesSameDomain verifies that two goroutines
// requesting a lock on the same domain serialize: the second blocks until
// the first releases. This is the cross-replica contract the orchestrator
// depends on to avoid duplicate ACME issuance.
func TestFlockLockerSerializesSameDomain(t *testing.T) {
	dir := t.TempDir()
	locker := newFlockLocker(dir, nil)

	const holdFor = 200 * time.Millisecond
	const minBlocked = 150 * time.Millisecond

	unlock1, err := locker.Lock(context.Background(), "example.com")
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	start := time.Now()
	var elapsed time.Duration

	go func() {
		defer wg.Done()
		unlock2, err := locker.Lock(context.Background(), "example.com")
		elapsed = time.Since(start)
		assert.NoError(t, err)
		if unlock2 != nil {
			unlock2()
		}
	}()

	time.Sleep(holdFor)
	unlock1()

	wg.Wait()
	assert.GreaterOrEqual(t, elapsed, minBlocked,
		"second Lock on same domain should have blocked for ~holdFor")
}

// TestFlockLockerDifferentDomainsParallel verifies that the locker does
// not serialize across distinct domains. Two goroutines locking different
// domains both proceed without contention.
func TestFlockLockerDifferentDomainsParallel(t *testing.T) {
	dir := t.TempDir()
	locker := newFlockLocker(dir, nil)

	const maxParallel = 100 * time.Millisecond

	var wg sync.WaitGroup
	wg.Add(2)

	start := time.Now()
	var elapsedA, elapsedB time.Duration

	go func() {
		defer wg.Done()
		unlock, err := locker.Lock(context.Background(), "a.example.com")
		elapsedA = time.Since(start)
		assert.NoError(t, err)
		if unlock != nil {
			unlock()
		}
	}()
	go func() {
		defer wg.Done()
		unlock, err := locker.Lock(context.Background(), "b.example.com")
		elapsedB = time.Since(start)
		assert.NoError(t, err)
		if unlock != nil {
			unlock()
		}
	}()

	wg.Wait()
	assert.Less(t, elapsedA, maxParallel,
		"locking distinct domains should not serialize (a)")
	assert.Less(t, elapsedB, maxParallel,
		"locking distinct domains should not serialize (b)")
}
