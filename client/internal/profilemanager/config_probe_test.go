package profilemanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeCertPair writes a throwaway certificate and key, so apply() has
// something real to load rather than a missing file it would only log about.
func writeCertPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "probe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// The dry run behind the update-settings gate must not read the mTLS pair off
// disk. The loaded pair feeds the connection, never the comparison, and the
// gate runs it on every SetConfig and Login — twice per request — including the
// ones it refuses.
func TestProbeDoesNotLoadTheCertificatePair(t *testing.T) {
	certPath, keyPath := writeCertPair(t)

	t.Run("a real apply loads it", func(t *testing.T) {
		config := newConfigSkeleton()
		config.ClientCertPath, config.ClientCertKeyPath = certPath, keyPath

		_, err := config.apply(ConfigInput{})
		require.NoError(t, err)
		require.NotNil(t, config.ClientCertKeyPair, "the connection would have no client certificate")
	})

	t.Run("a probe does not", func(t *testing.T) {
		config := newConfigSkeleton()
		config.ClientCertPath, config.ClientCertKeyPath = certPath, keyPath
		config.probing = true

		_, err := config.apply(ConfigInput{})
		require.NoError(t, err)
		require.Nil(t, config.ClientCertKeyPair, "the dry run read the certificate off disk")
	})

	// And the verdict is the same either way, which is the only thing the gate
	// asks of the probe.
	t.Run("the verdict is unaffected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "mtls.json")
		_, err := UpdateOrCreateConfig(ConfigInput{
			ConfigPath:        path,
			ManagementURL:     DefaultManagementURL,
			ClientCertPath:    certPath,
			ClientCertKeyPath: keyPath,
		})
		require.NoError(t, err)

		stored, err := GetExistingConfig(path)
		require.NoError(t, err)

		changed, err := stored.WouldChange(ConfigInput{ClientCertPath: certPath, ClientCertKeyPath: keyPath})
		require.NoError(t, err)
		require.False(t, changed, "restating the stored certificate paths is not a change")

		changed, err = stored.WouldChange(ConfigInput{ClientCertPath: filepath.Join(t.TempDir(), "other.crt")})
		require.NoError(t, err)
		require.True(t, changed, "a different certificate path is a change")
	})
}
