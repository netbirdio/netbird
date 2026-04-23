package entra_device

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueSelfSignedRSA produces a fresh RSA leaf cert with `deviceID` as Subject
// CN. The cert is self-signed (no trust root), valid for the given window.
func issueSelfSignedRSA(t *testing.T, deviceID string, notBefore, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed, key, base64.StdEncoding.EncodeToString(der)
}

func issueSelfSignedECDSA(t *testing.T, deviceID string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed, key, base64.StdEncoding.EncodeToString(der)
}

func signNonceRSA(t *testing.T, key *rsa.PrivateKey, nonce []byte) string {
	t.Helper()
	digest := sha256.Sum256(nonce)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

func signNoncePKCS1(t *testing.T, key *rsa.PrivateKey, nonce []byte) string {
	t.Helper()
	digest := sha256.Sum256(nonce)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

func signNonceECDSA(t *testing.T, key *ecdsa.PrivateKey, nonce []byte) string {
	t.Helper()
	digest := sha256.Sum256(nonce)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	sigBytes, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sigBytes)
}

// -------------------- tests --------------------

func TestCertValidator_RSA_PSS_HappyPath(t *testing.T) {
	deviceID := "00000000-aaaa-bbbb-cccc-111111111111"
	nonce := []byte("server-nonce-bytes")
	_, key, certB64 := issueSelfSignedRSA(t, deviceID,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	v := NewCertValidator(nil, nil) // no trust roots -> self-signed accepted

	identity, err := v.Validate([]string{certB64}, nonce, signNonceRSA(t, key, nonce))
	require.Nil(t, err, "expected success, got %+v", err)
	assert.Equal(t, deviceID, identity.EntraDeviceID)
	assert.NotEmpty(t, identity.CertThumbprint)
}

func TestCertValidator_RSA_PKCS1v15_HappyPath(t *testing.T) {
	// Some Windows CNG / SCEP stacks emit PKCS1v15 rather than PSS. Make sure
	// the validator accepts both.
	deviceID := "22222222-dddd-eeee-ffff-333333333333"
	nonce := []byte("different-nonce")
	_, key, certB64 := issueSelfSignedRSA(t, deviceID,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	v := NewCertValidator(nil, nil)

	identity, err := v.Validate([]string{certB64}, nonce, signNoncePKCS1(t, key, nonce))
	require.Nil(t, err, "expected success, got %+v", err)
	assert.Equal(t, deviceID, identity.EntraDeviceID)
}

func TestCertValidator_ECDSA_HappyPath(t *testing.T) {
	deviceID := "44444444-gggg-hhhh-iiii-555555555555"
	nonce := []byte("ecdsa-nonce-123")
	_, key, certB64 := issueSelfSignedECDSA(t, deviceID,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	v := NewCertValidator(nil, nil)

	identity, err := v.Validate([]string{certB64}, nonce, signNonceECDSA(t, key, nonce))
	require.Nil(t, err, "expected success, got %+v", err)
	assert.Equal(t, deviceID, identity.EntraDeviceID)
}

func TestCertValidator_RejectsTamperedSignature(t *testing.T) {
	nonce := []byte("good-nonce")
	_, key, certB64 := issueSelfSignedRSA(t, "device-x",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	v := NewCertValidator(nil, nil)

	// Sign a DIFFERENT nonce, then submit the "good" nonce -> must fail.
	sig := signNonceRSA(t, key, []byte("wrong-nonce"))
	_, verr := v.Validate([]string{certB64}, nonce, sig)
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidSignature, verr.Code)
}

func TestCertValidator_RejectsExpiredCert(t *testing.T) {
	nonce := []byte("n")
	_, key, certB64 := issueSelfSignedRSA(t, "device-x",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)) // expired

	v := NewCertValidator(nil, nil)
	_, verr := v.Validate([]string{certB64}, nonce, signNonceRSA(t, key, nonce))
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidCertChain, verr.Code)
}

func TestCertValidator_RejectsNotYetValidCert(t *testing.T) {
	nonce := []byte("n")
	_, key, certB64 := issueSelfSignedRSA(t, "device-x",
		time.Now().Add(1*time.Hour), time.Now().Add(2*time.Hour)) // not yet valid

	v := NewCertValidator(nil, nil)
	_, verr := v.Validate([]string{certB64}, nonce, signNonceRSA(t, key, nonce))
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidCertChain, verr.Code)
}

func TestCertValidator_RejectsEmptyChain(t *testing.T) {
	v := NewCertValidator(nil, nil)
	_, verr := v.Validate(nil, []byte("n"), "")
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidCertChain, verr.Code)
}

func TestCertValidator_RejectsGarbageBase64(t *testing.T) {
	v := NewCertValidator(nil, nil)
	_, verr := v.Validate([]string{"not-base64!!!"}, []byte("n"), "")
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidCertChain, verr.Code)
}

func TestCertValidator_RejectsGarbageDER(t *testing.T) {
	v := NewCertValidator(nil, nil)
	_, verr := v.Validate([]string{base64.StdEncoding.EncodeToString([]byte("hello"))}, []byte("n"), "")
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidCertChain, verr.Code)
}

func TestCertValidator_ChainVerificationWithRoots(t *testing.T) {
	// When TrustRoots is non-nil, the leaf's chain MUST verify. A random
	// self-signed leaf whose CA isn't in the pool is rejected.
	deviceID := "trust-enforced"
	nonce := []byte("n")
	_, key, certB64 := issueSelfSignedRSA(t, deviceID,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	// Empty (but non-nil) roots pool -> no anchors accepted -> reject.
	v := NewCertValidator(x509.NewCertPool(), nil)
	_, verr := v.Validate([]string{certB64}, nonce, signNonceRSA(t, key, nonce))
	require.NotNil(t, verr)
	assert.Equal(t, CodeInvalidCertChain, verr.Code)
}
