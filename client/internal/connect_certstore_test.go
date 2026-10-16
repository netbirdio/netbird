package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/certproof"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// TestCertStoreConfig_ReadsEnvironmentNotProfile: the token URI may carry the PIN, so it
// and the store directory come from the daemon's environment, and values left in the
// profile config from an older version are ignored.
func TestCertStoreConfig_ReadsEnvironmentNotProfile(t *testing.T) {
	t.Setenv(certproof.PKCS11URIEnv, "pkcs11:token=env")
	t.Setenv(certproof.PINEnv, "1234")

	cfg := certStoreConfig(&profilemanager.Config{
		CertStoreDir:  "/from/profile",
		CertPKCS11URI: "pkcs11:token=profile?pin-value=9999",
	})

	assert.Equal(t, "pkcs11:token=env", cfg.PKCS11.URI, "the URI comes from the environment")
	assert.Equal(t, "1234", cfg.PKCS11.PIN, "the PIN comes from the environment")
}
