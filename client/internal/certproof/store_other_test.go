//go:build !darwin && !windows

package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoreWithToken(t *testing.T) {
	assert.IsType(t, &FileStore{}, storeWithToken(PKCS11Config{}), "nothing configured reads the PEM directory alone")
	assert.IsType(t, &FileStore{}, storeWithToken(PKCS11Config{URI: "not-a-pkcs11-uri"}), "an invalid URI must not hide the PEM directory")

	for name, cfg := range map[string]PKCS11Config{
		"pin alone": {PIN: "1234"},
		"uri alone": {URI: "pkcs11:token=netbird?pin-value=1234"},
	} {
		store, ok := storeWithToken(cfg).(Stores)
		if assert.True(t, ok, "%s joins the token to the PEM directory", name) {
			assert.Len(t, store, 2, name)
			assert.IsType(t, &PKCS11Store{}, store[1], name)
		}
	}
}
