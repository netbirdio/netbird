package certwatch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateSelfSignedCert(t *testing.T, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func writeCert(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600))
}

func TestNewWatcher(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, 1)
	writeCert(t, dir, certPEM, keyPEM)

	w, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	require.NoError(t, err)

	cert, err := w.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, int64(1), cert.Leaf.SerialNumber.Int64())
}

func TestNewWatcherMissingFiles(t *testing.T) {
	dir := t.TempDir()

	_, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	assert.Error(t, err)
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	certPEM1, keyPEM1 := generateSelfSignedCert(t, 100)
	writeCert(t, dir, certPEM1, keyPEM1)

	w, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	require.NoError(t, err)

	cert1, err := w.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, int64(100), cert1.Leaf.SerialNumber.Int64())

	// Write a new cert with a different serial.
	certPEM2, keyPEM2 := generateSelfSignedCert(t, 200)
	writeCert(t, dir, certPEM2, keyPEM2)

	// Manually trigger reload.
	w.tryReload()

	cert2, err := w.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, int64(200), cert2.Leaf.SerialNumber.Int64())
}

func TestTryReloadSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, 42)
	writeCert(t, dir, certPEM, keyPEM)

	w, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	require.NoError(t, err)

	cert1, err := w.GetCertificate(nil)
	require.NoError(t, err)

	// Reload with same cert - pointer should remain the same.
	w.tryReload()

	cert2, err := w.GetCertificate(nil)
	require.NoError(t, err)
	assert.Same(t, cert1, cert2, "cert pointer should not change when content is the same")
}

func TestWatchDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	certPEM1, keyPEM1 := generateSelfSignedCert(t, 1)
	writeCert(t, dir, certPEM1, keyPEM1)

	w, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	require.NoError(t, err)

	// Use a short poll interval for the test.
	w.pollInterval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.Watch(ctx)

	// Write new cert.
	certPEM2, keyPEM2 := generateSelfSignedCert(t, 999)
	writeCert(t, dir, certPEM2, keyPEM2)

	// Wait for the watcher to pick it up.
	require.Eventually(t, func() bool {
		cert, err := w.GetCertificate(nil)
		if err != nil {
			return false
		}
		return cert.Leaf.SerialNumber.Int64() == 999
	}, 5*time.Second, 50*time.Millisecond, "watcher should detect cert change")
}

func TestIsRelevantFile(t *testing.T) {
	assert.True(t, isRelevantFile("tls.crt", "tls.crt", "tls.key"))
	assert.True(t, isRelevantFile("tls.key", "tls.crt", "tls.key"))
	assert.True(t, isRelevantFile("..data", "tls.crt", "tls.key"))
	assert.False(t, isRelevantFile("other.txt", "tls.crt", "tls.key"))
}

// TestWatchSymlinkRotation simulates Kubernetes secret volume updates where
// the data directory is atomically swapped via a ..data symlink.
func TestWatchSymlinkRotation(t *testing.T) {
	base := t.TempDir()

	// Create initial target directory with certs.
	dir1 := filepath.Join(base, "dir1")
	require.NoError(t, os.Mkdir(dir1, 0o755))
	certPEM1, keyPEM1 := generateSelfSignedCert(t, 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "tls.crt"), certPEM1, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "tls.key"), keyPEM1, 0o600))

	// Create ..data symlink pointing to dir1.
	dataLink := filepath.Join(base, "..data")
	require.NoError(t, os.Symlink(dir1, dataLink))

	// Create tls.crt and tls.key as symlinks to ..data/{file}.
	certLink := filepath.Join(base, "tls.crt")
	keyLink := filepath.Join(base, "tls.key")
	require.NoError(t, os.Symlink(filepath.Join(dataLink, "tls.crt"), certLink))
	require.NoError(t, os.Symlink(filepath.Join(dataLink, "tls.key"), keyLink))

	w, err := NewWatcher(certLink, keyLink, nil)
	require.NoError(t, err)

	cert, err := w.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cert.Leaf.SerialNumber.Int64())

	w.pollInterval = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.Watch(ctx)

	// Simulate k8s atomic rotation: create dir2, swap ..data symlink.
	dir2 := filepath.Join(base, "dir2")
	require.NoError(t, os.Mkdir(dir2, 0o755))
	certPEM2, keyPEM2 := generateSelfSignedCert(t, 777)
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "tls.crt"), certPEM2, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "tls.key"), keyPEM2, 0o600))

	// Atomic swap: create temp link, then rename over ..data.
	tmpLink := filepath.Join(base, "..data_tmp")
	require.NoError(t, os.Symlink(dir2, tmpLink))
	require.NoError(t, os.Rename(tmpLink, dataLink))

	require.Eventually(t, func() bool {
		cert, err := w.GetCertificate(nil)
		if err != nil {
			return false
		}
		return cert.Leaf.SerialNumber.Int64() == 777
	}, 5*time.Second, 50*time.Millisecond, "watcher should detect symlink rotation")
}

// TestPollLoopDetectsChanges verifies the poll-only fallback path works.
func TestPollLoopDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	certPEM1, keyPEM1 := generateSelfSignedCert(t, 1)
	writeCert(t, dir, certPEM1, keyPEM1)

	w, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	require.NoError(t, err)

	w.pollInterval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Directly use pollLoop to test the fallback path.
	go w.pollLoop(ctx)

	certPEM2, keyPEM2 := generateSelfSignedCert(t, 555)
	writeCert(t, dir, certPEM2, keyPEM2)

	require.Eventually(t, func() bool {
		cert, err := w.GetCertificate(nil)
		if err != nil {
			return false
		}
		return cert.Leaf.SerialNumber.Int64() == 555
	}, 5*time.Second, 50*time.Millisecond, "poll loop should detect cert change")
}

func TestGetCertificateConcurrency(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, 1)
	writeCert(t, dir, certPEM, keyPEM)

	w, err := NewWatcher(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		nil,
	)
	require.NoError(t, err)

	// Hammer GetCertificate concurrently while reloading.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			w.tryReload()
		}
		close(done)
	}()

	for i := 0; i < 1000; i++ {
		cert, err := w.GetCertificate(&tls.ClientHelloInfo{})
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	}

	<-done
}
