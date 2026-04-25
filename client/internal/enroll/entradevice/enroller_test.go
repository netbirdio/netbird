package entradevice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// makeSelfSignedPFX produces a .pfx file on disk whose leaf has the given
// Subject CN. Returns (path, password).
func makeSelfSignedPFX(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// Standard pkcs12.Modern produces a PFX that both Windows and most
	// third-party tools can consume.
	password := "entra-test-pass"
	pfxBytes, err := pkcs12.Modern.Encode(key, leaf, nil, password)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "device.pfx")
	require.NoError(t, os.WriteFile(path, pfxBytes, 0o600))
	return path, password
}

// -------------------- PFXProvider --------------------

func TestPFXProvider_LoadAndSign(t *testing.T) {
	cn := "00000000-aaaa-bbbb-cccc-111111111111"
	pfxPath, pfxPass := makeSelfSignedPFX(t, cn)

	p, err := LoadPFX(pfxPath, pfxPass)
	require.NoError(t, err)

	id, err := p.DeviceID()
	require.NoError(t, err)
	assert.Equal(t, cn, id)

	chain, err := p.CertChainDER()
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.NotEmpty(t, chain[0])

	sig, err := p.SignNonce([]byte("hello world"))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestPFXProvider_WrongPasswordIsRejected(t *testing.T) {
	pfxPath, _ := makeSelfSignedPFX(t, "cn")
	_, err := LoadPFX(pfxPath, "wrong")
	require.Error(t, err)
}

func TestPFXProvider_BadPath(t *testing.T) {
	_, err := LoadPFX(filepath.Join(t.TempDir(), "nope.pfx"), "x")
	require.Error(t, err)
}

// -------------------- Enroller --------------------

// fakeServer stands up an httptest server that mimics /join/entra.
type fakeServer struct {
	*httptest.Server
	gotEnroll *enrollReq
}

func newFakeServer(t *testing.T, handle func(req enrollReq) (int, any)) *fakeServer {
	t.Helper()
	fs := &fakeServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/join/entra/challenge", func(w http.ResponseWriter, r *http.Request) {
		// Emit a URL-safe base64 nonce, like the real server does.
		var nonceBytes [32]byte
		_, _ = rand.Read(nonceBytes[:])
		resp := challengeResp{
			Nonce:     base64.RawURLEncoding.EncodeToString(nonceBytes[:]),
			ExpiresAt: time.Now().Add(30 * time.Second),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/join/entra/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req enrollReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		fs.gotEnroll = &req
		status, body := handle(req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	fs.Server = httptest.NewServer(mux)
	return fs
}

func TestEnroller_HappyPath(t *testing.T) {
	pfxPath, pfxPass := makeSelfSignedPFX(t, "device-001")
	cert, err := LoadPFX(pfxPath, pfxPass)
	require.NoError(t, err)

	fs := newFakeServer(t, func(req enrollReq) (int, any) {
		// Spot-check the incoming request shape.
		return http.StatusOK, enrollResp{
			PeerID:                   "peer-xyz",
			EnrollmentBootstrapToken: "deadbeef",
			ResolvedAutoGroups:       []string{"nb-vpn"},
			MatchedMappingIDs:        []string{"m-1"},
			ResolutionMode:           "strict_priority",
		}
	})
	defer fs.Close()

	en := &Enroller{
		BaseURL:  fs.URL,
		Cert:     cert,
		TenantID: "tenant-1",
		WGPubKey: "dLzQpmQzNkow7EkXHM5e461Z1sM4q/1tVp1kGxKZmgU=",
		Hostname: "laptop-1",
	}
	state, err := en.Enrol(context.Background())
	require.NoError(t, err)

	// Client produced a good state.
	assert.True(t, state.IsEnrolled())
	assert.Equal(t, "peer-xyz", state.PeerID)
	assert.Equal(t, "tenant-1", state.TenantID)
	assert.Equal(t, "device-001", state.EntraDeviceID)
	assert.Equal(t, "strict_priority", state.ResolutionMode)
	assert.Equal(t, []string{"nb-vpn"}, state.ResolvedAutoGroups)

	// Server received a well-formed request.
	require.NotNil(t, fs.gotEnroll)
	assert.Equal(t, "tenant-1", fs.gotEnroll.TenantID)
	assert.Equal(t, "device-001", fs.gotEnroll.EntraDeviceID)
	assert.Equal(t, "dLzQpmQzNkow7EkXHM5e461Z1sM4q/1tVp1kGxKZmgU=", fs.gotEnroll.WGPubKey)
	assert.Equal(t, "laptop-1", fs.gotEnroll.Hostname)
	assert.Len(t, fs.gotEnroll.CertChain, 1)
	assert.NotEmpty(t, fs.gotEnroll.Nonce)
	assert.NotEmpty(t, fs.gotEnroll.NonceSignature)
}

func TestEnroller_StructuredServerError(t *testing.T) {
	pfxPath, pfxPass := makeSelfSignedPFX(t, "dev")
	cert, err := LoadPFX(pfxPath, pfxPass)
	require.NoError(t, err)

	fs := newFakeServer(t, func(req enrollReq) (int, any) {
		return http.StatusForbidden, map[string]string{
			"code":    "no_mapping_matched",
			"message": "device is not a member of any mapped Entra group",
		}
	})
	defer fs.Close()

	en := &Enroller{
		BaseURL:  fs.URL,
		Cert:     cert,
		TenantID: "t",
		WGPubKey: "k",
	}
	_, err = en.Enrol(context.Background())
	require.Error(t, err)

	var ee *Error
	require.ErrorAs(t, err, &ee, "server errors should decode to *Error so callers can branch on Code")
	assert.Equal(t, "no_mapping_matched", ee.Code)
	assert.Equal(t, http.StatusForbidden, ee.HTTPStatus)
	assert.Equal(t, "enroll", ee.Stage)
}

func TestEnroller_RequiresCertAndKeys(t *testing.T) {
	en := &Enroller{TenantID: "t", WGPubKey: "k"}
	_, err := en.Enrol(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Cert is required")

	// With cert but no tenant
	pfxPath, pfxPass := makeSelfSignedPFX(t, "dev")
	cert, _ := LoadPFX(pfxPath, pfxPass)
	en = &Enroller{Cert: cert, WGPubKey: "k"}
	_, err = en.Enrol(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TenantID is required")

	// With cert + tenant but no WG key
	en = &Enroller{Cert: cert, TenantID: "t"}
	_, err = en.Enrol(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WGPubKey is required")
}

func TestEnroller_StripsTrailingJoinEntraFromBaseURL(t *testing.T) {
	// If the operator passes --management-url https://mgmt/join/entra (as
	// the UX encourages), the enroller must still build challenge/enroll at
	// the right paths without doubling the suffix.
	pfxPath, pfxPass := makeSelfSignedPFX(t, "dev")
	cert, _ := LoadPFX(pfxPath, pfxPass)

	fs := newFakeServer(t, func(req enrollReq) (int, any) {
		return http.StatusOK, enrollResp{PeerID: "peer-1"}
	})
	defer fs.Close()

	en := &Enroller{
		BaseURL:  fs.URL + "/join/entra",
		Cert:     cert,
		TenantID: "t",
		WGPubKey: "k",
	}
	state, err := en.Enrol(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "peer-1", state.PeerID)
}

// Compile-time assertions.
var _ CertProvider = (*PFXProvider)(nil)

// Silence unused-import warning on Go versions without error.As shortcut.
var _ = fmt.Sprintf
