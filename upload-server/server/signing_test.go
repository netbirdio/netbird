package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/types"
)

func newLocalMux(t *testing.T) (*http.ServeMux, string) {
	t.Helper()

	mockDir := t.TempDir()
	t.Setenv("SERVER_URL", "https://localhost:8080")
	t.Setenv("STORE_DIR", mockDir)
	t.Setenv(signingKeyVar, testSigningKey)

	mux := http.NewServeMux()
	require.NoError(t, configureLocalHandlers(mux, newTestRateLimiter(t)))

	return mux, mockDir
}

func Test_LocalUploadURLRoundTrip(t *testing.T) {
	mux, mockDir := newLocalMux(t)

	getReq := httptest.NewRequest(http.MethodGet, types.GetURLPath+"?id=test-file", nil)
	getReq.Header.Set(types.ClientHeader, types.ClientHeaderValue)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code)

	var response types.GetURLResponse
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &response))

	minted, err := url.Parse(response.URL)
	require.NoError(t, err)
	require.NotEmpty(t, minted.Query().Get(signatureParam))

	content := []byte("bundle")
	putRec := httptest.NewRecorder()
	mux.ServeHTTP(putRec, httptest.NewRequest(http.MethodPut, minted.RequestURI(), bytes.NewReader(content)))
	require.Equal(t, http.StatusOK, putRec.Code)

	written, err := os.ReadFile(filepath.Join(mockDir, response.Key))
	require.NoError(t, err)
	require.Equal(t, content, written)
}

func Test_LocalHandlePutRequest_RejectsUnauthorized(t *testing.T) {
	expired := &signer{key: []byte(testSigningKey)}

	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "no signature",
			query: "",
		},
		{
			name:  "tampered signature",
			query: "exp=99999999999&sig=deadbeef",
		},
		{
			name:  "malformed signature",
			query: "exp=99999999999&sig=not-hex",
		},
		{
			// A signature is only good for the key it was minted for, so a URL
			// handed out for one bundle cannot be replayed against another.
			name:  "signature for a different object",
			query: signedQuery(t, "dir/other.txt"),
		},
		{
			name:  "signature expiring this second",
			query: expired.sign("dir/file.txt", time.Now().Add(-signatureTTL)).Encode(),
		},
		{
			name:  "expired signature",
			query: expired.sign("dir/file.txt", time.Now().Add(-signatureTTL-time.Minute)).Encode(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux, mockDir := newLocalMux(t)

			target := putURLPath + "/dir/file.txt"
			if tc.query != "" {
				target += "?" + tc.query
			}

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, target, bytes.NewReader([]byte("payload"))))

			require.Equal(t, http.StatusUnauthorized, rec.Code)

			_, err := os.Stat(filepath.Join(mockDir, "dir", "file.txt"))
			require.True(t, os.IsNotExist(err), "unauthorized upload should not be written")
		})
	}
}

func Test_SignerRejectsForeignKey(t *testing.T) {
	minted := (&signer{key: []byte("one key")}).sign("dir/file.txt", time.Now())

	err := (&signer{key: []byte("another key")}).verify("dir/file.txt", minted, time.Now())
	require.Error(t, err)
}

func Test_NewSignerGeneratesEphemeralKey(t *testing.T) {
	// Registers the restore hook, then clears the value for this test only.
	t.Setenv(signingKeyVar, "")
	os.Unsetenv(signingKeyVar)

	first, err := newSigner()
	require.NoError(t, err)
	second, err := newSigner()
	require.NoError(t, err)

	require.NotEqual(t, first.key, second.key)
	require.Len(t, first.key, 32)
}

func Test_NewSignerRejectsEmptyKey(t *testing.T) {
	t.Setenv(signingKeyVar, "")

	_, err := newSigner()
	require.Error(t, err)
}

func Test_NewSignerRejectsShortKey(t *testing.T) {
	t.Setenv(signingKeyVar, strings.Repeat("a", minSigningKeyLen-1))

	_, err := newSigner()
	require.Error(t, err)
}
