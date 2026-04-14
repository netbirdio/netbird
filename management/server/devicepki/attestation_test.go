package devicepki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
)

// generateEKCert creates a self-signed EK certificate for testing.
func generateEKCert(t *testing.T) (ekCertDER []byte, _ *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test TPM EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return der, key
}

// generateAKKeyPair creates an AK key pair and returns the public DER and private key.
func generateAKKeyPair(t *testing.T) (akPubDER []byte, akPriv *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return pubDER, key
}

// signCertifyInfo signs certifyInfo with the AK key, returning an ASN.1 DER signature.
func signCertifyInfo(t *testing.T, key *ecdsa.PrivateKey, certifyInfo []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(certifyInfo)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	return sig
}

func TestVerifyAttestation_ValidProof(t *testing.T) {
	ekCertDER, _ := generateEKCert(t)
	akPubDER, akPriv := generateAKKeyPair(t)
	certifyInfo := []byte("tpms_attest_blob_for_testing")
	sig := signCertifyInfo(t, akPriv, certifyInfo)

	// EK cert pool is empty in open-source build → chain check is skipped.
	err := devicepki.VerifyAttestation(ekCertDER, akPubDER, certifyInfo, sig)
	require.NoError(t, err)
}

func TestVerifyAttestation_EmptyFields(t *testing.T) {
	ekCertDER, _ := generateEKCert(t)
	akPubDER, akPriv := generateAKKeyPair(t)
	certifyInfo := []byte("attest")
	sig := signCertifyInfo(t, akPriv, certifyInfo)

	tests := []struct {
		name             string
		ekCertDER        []byte
		akPubDER         []byte
		certifyInfo      []byte
		certifySignature []byte
	}{
		{"empty ekCert", nil, akPubDER, certifyInfo, sig},
		{"empty akPub", ekCertDER, nil, certifyInfo, sig},
		{"empty certifyInfo", ekCertDER, akPubDER, nil, sig},
		{"empty sig", ekCertDER, akPubDER, certifyInfo, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := devicepki.VerifyAttestation(tc.ekCertDER, tc.akPubDER, tc.certifyInfo, tc.certifySignature)
			require.Error(t, err)
		})
	}
}

func TestVerifyAttestation_InvalidEKCert(t *testing.T) {
	_, akPriv := generateAKKeyPair(t)
	akPubDER, _ := generateAKKeyPair(t)
	certifyInfo := []byte("attest")
	sig := signCertifyInfo(t, akPriv, certifyInfo)

	err := devicepki.VerifyAttestation([]byte("not a valid DER cert"), akPubDER, certifyInfo, sig)
	require.Error(t, err)
}

func TestVerifyAttestation_BadSignature(t *testing.T) {
	ekCertDER, _ := generateEKCert(t)
	akPubDER, _ := generateAKKeyPair(t)
	certifyInfo := []byte("attest")

	// Sign with a different key — verification must fail.
	_, otherKey := generateAKKeyPair(t)
	sig := signCertifyInfo(t, otherKey, certifyInfo)

	err := devicepki.VerifyAttestation(ekCertDER, akPubDER, certifyInfo, sig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AK signature verification failed")
}

func TestVerifyAttestation_InvalidAKPubDER(t *testing.T) {
	ekCertDER, _ := generateEKCert(t)
	certifyInfo := []byte("attest")

	// Produce garbage DER (valid ASN.1 but not a public key).
	garbage, _ := asn1.Marshal("not a key")

	err := devicepki.VerifyAttestation(ekCertDER, garbage, certifyInfo, []byte("sig"))
	require.Error(t, err)
}
