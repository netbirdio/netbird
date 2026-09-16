package pkcs11

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURI(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantToken  string
		wantModule string
		wantPIN    []byte
	}{
		{
			name:       "token with module path and pin value",
			raw:        "pkcs11:token=netbird?module-path=/usr/lib/libtpm2_pkcs11.so&pin-value=1234",
			wantToken:  "netbird",
			wantModule: "/usr/lib/libtpm2_pkcs11.so",
			wantPIN:    []byte("1234"),
		},
		{
			name:       "module name becomes a library file",
			raw:        "pkcs11:token=netbird?module-name=tpm2_pkcs11",
			wantToken:  "netbird",
			wantModule: "libtpm2_pkcs11.so",
		},
		{
			name:       "percent encoding and unknown attributes",
			raw:        "pkcs11:model=SoftHSM%20v2;token=my%20token;serial=1?max-sessions=1",
			wantToken:  "my token",
			wantModule: DefaultModule,
		},
		{
			name:       "bare scheme uses the p11-kit proxy and no login",
			raw:        "pkcs11:",
			wantModule: DefaultModule,
		},
		{
			name:       "empty pin value still logs in",
			raw:        "pkcs11:?pin-value=",
			wantModule: DefaultModule,
			wantPIN:    []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := ParseURI(tt.raw)
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, uri.Token, "token label")
			assert.Equal(t, tt.wantModule, uri.Module(), "module to load")
			pin, err := uri.PIN()
			require.NoError(t, err)
			assert.Equal(t, tt.wantPIN, pin, "PIN, nil meaning no login")
		})
	}
}

func TestParseURI_Rejections(t *testing.T) {
	for _, raw := range []string{"pkcs11", "https://example.com", "pkcs11:token", "pkcs11:token=%zz"} {
		_, err := ParseURI(raw)
		assert.Error(t, err, raw)
	}
}

func TestURI_PINFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(path, []byte("secret\n"), 0o600))

	for _, source := range []string{path, "file:" + path, "file://" + path} {
		uri, err := ParseURI("pkcs11:token=netbird?pin-source=" + source)
		require.NoError(t, err)
		pin, err := uri.PIN()
		require.NoError(t, err)
		assert.Equal(t, []byte("secret"), pin, "PIN from %s must drop the trailing newline", source)
	}

	uri, err := ParseURI("pkcs11:?pin-source=" + filepath.Join(t.TempDir(), "missing"))
	require.NoError(t, err)
	_, err = uri.PIN()
	assert.Error(t, err, "a missing PIN file must fail loudly instead of logging in without a PIN")
}
