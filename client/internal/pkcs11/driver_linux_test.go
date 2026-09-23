//go:build pkcs11 && linux && (amd64 || arm64)

package pkcs11

import (
	"crypto/x509"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructLayoutsMatchTheCABI(t *testing.T) {
	assert.Equal(t, uintptr(24), unsafe.Sizeof(attribute{}), "CK_ATTRIBUTE")
	assert.Equal(t, uintptr(24), unsafe.Sizeof(mechanism{}), "CK_MECHANISM")
	assert.Equal(t, uintptr(24), unsafe.Sizeof(pssParams{}), "CK_RSA_PKCS_PSS_PARAMS")
	assert.Equal(t, uintptr(208), unsafe.Sizeof(tokenInfo{}), "CK_TOKEN_INFO")
	assert.Equal(t, uintptr(48), unsafe.Sizeof(initializeArgs{}), "CK_C_INITIALIZE_ARGS")
	assert.Equal(t, uintptr(8), unsafe.Offsetof(functionList{}.fn), "entry points follow the padded CK_VERSION")
	assert.Equal(t, uintptr(8+68*8), unsafe.Sizeof(functionList{}), "CK_FUNCTION_LIST v2.40")
}

// TestTrustModule_ListsSystemCertificates drives a real module through the binding:
// p11-kit's trust module exposes the system CA store as certificate objects with no login.
func TestTrustModule_ListsSystemCertificates(t *testing.T) {
	module := loadFirst(t,
		"/usr/lib/pkcs11/p11-kit-trust.so",
		"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
		"/usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-trust.so",
		"/usr/lib64/pkcs11/p11-kit-trust.so",
	)

	tokens, err := module.Tokens()
	require.NoError(t, err)
	require.NotEmpty(t, tokens, "the trust module must present at least one token")

	parsed := 0
	for _, token := range tokens {
		session, err := module.OpenSession(token.Label, nil)
		require.NoError(t, err, token.Label)
		objects, err := session.FindObjects(
			Attribute{Type: AttrClass, Value: ULong(ClassCertificate)},
			Attribute{Type: AttrCertificateType, Value: ULong(CertificateX509)},
		)
		require.NoError(t, err, token.Label)
		for _, object := range objects {
			der, err := session.Attribute(object, AttrValue)
			require.NoError(t, err)
			_, err = x509.ParseCertificate(der)
			require.NoError(t, err, "CKA_VALUE must be a DER certificate")
			parsed++
		}
		session.Close()
	}
	assert.Positive(t, parsed, "system trust anchors must be readable through the binding")
}

func loadFirst(t *testing.T, paths ...string) *Module {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		module, err := Load(path)
		require.NoError(t, err, path)
		return module
	}
	t.Skip("p11-kit trust module not installed")
	return nil
}
