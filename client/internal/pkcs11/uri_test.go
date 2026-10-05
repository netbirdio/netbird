package pkcs11

import (
	"os"
	"path/filepath"
	"runtime"
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
			raw:        "pkcs11:token=netbird?module-path=" + absModule("libtpm2_pkcs11.so") + "&pin-value=1234",
			wantToken:  "netbird",
			wantModule: absModule("libtpm2_pkcs11.so"),
			wantPIN:    []byte("1234"),
		},
		{
			name:       "module name becomes a library file",
			raw:        "pkcs11:token=netbird?module-name=tpm2_pkcs11",
			wantToken:  "netbird",
			wantModule: "libtpm2_pkcs11.so",
		},
		{
			name:       "percent encoding, unknown query attributes are ignored",
			raw:        "pkcs11:token=my%20token?max-sessions=1&vendor-flag=on",
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
	tests := map[string]string{
		"no scheme":            "pkcs11",
		"other scheme":         "https://example.com",
		"attribute no value":   "pkcs11:token",
		"bad percent encoding": "pkcs11:token=%zz",
		// RFC 7512 2.3: an unrecognized path attribute matches nothing. Ignoring it
		// instead would let the token listed first answer for the one serial names.
		"unsupported serial":      "pkcs11:token=netbird;serial=1234",
		"unsupported model":       "pkcs11:model=SoftHSM%20v2;token=netbird",
		"object selector":         "pkcs11:token=netbird;object=device",
		"vendor path attribute":   "pkcs11:token=netbird;vendor-slot=2",
		"duplicate token":         "pkcs11:token=a;token=b",
		"duplicate module-path":   "pkcs11:token=a?module-path=" + absModule("a.so") + "&module-path=" + absModule("b.so"),
		"duplicate pin-value":     "pkcs11:token=a?pin-value=1&pin-value=2",
		"relative module-path":    "pkcs11:token=a?module-path=lib/x.so",
		"bare module-path":        "pkcs11:token=a?module-path=libtpm2_pkcs11.so",
		"module-name with path":   "pkcs11:token=a?module-name=../../tmp/evil",
		"module-name with slash":  "pkcs11:token=a?module-name=tmp/evil",
		"module-name with dotdot": "pkcs11:token=a?module-name=..",
		"empty module-name":       "pkcs11:token=a?module-name=",
	}
	for name, raw := range tests {
		_, err := ParseURI(raw)
		assert.Error(t, err, "%s: %s must be refused", name, raw)
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

// absModule is an absolute module path on the platform the test runs on, as module-path
// must be absolute.
func absModule(name string) string {
	if runtime.GOOS == "windows" {
		return `C:\lib\` + name
	}
	return "/lib/" + name
}
