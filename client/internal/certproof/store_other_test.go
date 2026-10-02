//go:build (!darwin && !windows) || ios

package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/pkcs11"
)

func TestStoreWithToken(t *testing.T) {
	dir := t.TempDir()

	files, ok := storeWithToken(Config{Dir: dir}).(*FileStore)
	require.True(t, ok, "a directory alone reads that directory alone")
	assert.Equal(t, dir, files.dir, "the configured directory replaces the default")

	files, ok = storeWithToken(Config{}).(*FileStore)
	require.True(t, ok, "nothing configured reads the PEM directory alone")
	assert.Equal(t, StoreDir(), files.dir, "no directory configured falls back to the environment or the default")

	assert.IsType(t, &FileStore{}, storeWithToken(Config{PKCS11: PKCS11Config{URI: "not-a-pkcs11-uri"}}), "an invalid URI must not hide the PEM directory")
	assert.IsType(t, &FileStore{}, storeWithToken(Config{PKCS11: PKCS11Config{PIN: "1234"}}), "a PIN naming no token is refused and leaves the PEM directory")

	configured := map[string]PKCS11Config{
		"env pin with token uri": {URI: "pkcs11:token=netbird", PIN: "1234"},
		"uri alone":              {URI: "pkcs11:token=netbird?pin-value=1234"},
	}
	if !pkcs11.Supported() {
		for name, cfg := range configured {
			assert.IsType(t, &FileStore{}, storeWithToken(Config{Dir: dir, PKCS11: cfg}),
				"%s: a build without PKCS#11 support reads the PEM directory alone", name)
		}
		return
	}
	for name, cfg := range configured {
		store, ok := storeWithToken(Config{Dir: dir, PKCS11: cfg}).(Stores)
		require.True(t, ok, "%s joins the token to the PEM directory", name)
		require.Len(t, store, 2, name)
		token, ok := store[1].(*PKCS11Store)
		require.True(t, ok, name)
		assert.Equal(t, dir, token.certDir, "%s: the token pairs certificates from the same directory", name)
	}
}
