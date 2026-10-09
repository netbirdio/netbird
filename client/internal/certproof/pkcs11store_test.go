package certproof

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/pkcs11"
	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const testPKCS11URIEnv = "NB_TEST_PKCS11_URI"

type failingStore struct{}

func (failingStore) Candidates(context.Context) ([]Candidate, error) {
	return nil, errors.New("token unplugged")
}

func TestStores_KeepsFileCertificatesWhenTokenFails(t *testing.T) {
	ca := certtest.NewCA(t, "corp")
	key := certtest.ECDSAKey(t)
	dir := t.TempDir()
	writeFile(t, dir, "device.pem", certtest.CertPEM(ca.Issue(t, key, "device"))+certtest.KeyPEM(t, key))

	candidates, err := Stores{failingStore{}, NewFileStore(dir)}.Candidates(context.Background())
	require.NoError(t, err)
	assert.Len(t, candidates, 1, "the directory's certificate must survive a failing token")
}

// TestCollect_PKCS11TokenEndToEnd needs an initialised token with a user PIN, named by
// NB_TEST_PKCS11_URI. With SoftHSM:
//
//	softhsm2-util --init-token --free --label netbird --pin 1234 --so-pin 1234
//	NB_TEST_PKCS11_URI='pkcs11:token=netbird?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234' \
//	  go test -tags pkcs11 ./client/internal/certproof/ -run PKCS11 -v
//
// It imports a key and its certificate as token objects, then proves the certificate
// through the store the way the daemon would. Every run adds one more identity to the token.
func TestCollect_PKCS11TokenEndToEnd(t *testing.T) {
	store, uri := pkcs11TestStore(t, "")

	keys := map[string]crypto.Signer{"ecdsa": certtest.ECDSAKey(t), "rsa": certtest.RSAKey(t)}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			ca := certtest.NewCA(t, "corp-"+name)
			leaf := ca.Issue(t, key, "device-"+name)
			importIdentity(t, uri, key, leaf)

			challenger := certposture.NewChallenger([]byte("secret"))
			now := time.Now()
			nonce := challenger.Nonce(peerKey, now)
			checks := []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{Nonce: nonce, CaCertificates: []string{ca.PEM}}}}

			proofs := Collect(context.Background(), store, checks, peerKey)
			require.Len(t, proofs, 1, "the token-held key must prove exactly this run's certificate")
			chain, err := challenger.Verify(proofs[0], peerKey, now)
			require.NoError(t, err)
			assert.True(t, leaf.Equal(chain[0]), "proof must carry the imported certificate")
		})
	}
}

// Attribute types the import needs and the store does not.
const (
	attrPrivate         = 0x2
	attrIssuer          = 0x81
	attrSerialNumber    = 0x82
	attrSensitive       = 0x103
	attrSign            = 0x108
	attrVerify          = 0x10a
	attrPrivateExponent = 0x123
	attrPrime1          = 0x124
	attrPrime2          = 0x125
	attrExponent1       = 0x126
	attrExponent2       = 0x127
	attrCoefficient     = 0x128
)

var (
	ckTrue  = []byte{1}
	ckFalse = []byte{0}
	// The P-256 named curve OID in DER, which is what CKA_EC_PARAMS carries.
	oidP256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
)

// importIdentity stores key and leaf on the token the way tpm2_ptool import and addcert
// do: private and public key objects plus the certificate, all under one CKA_ID.
func importIdentity(t *testing.T, uri string, key crypto.Signer, leaf *x509.Certificate) {
	t.Helper()
	id := importKey(t, uri, key, leaf.Subject.CommonName)
	importCertificate(t, uri, leaf, id)
}

func importKey(t *testing.T, uri string, key crypto.Signer, label string) []byte {
	t.Helper()
	session := readWriteSession(t, uri)
	defer session.Close()

	id := make([]byte, 8)
	_, err := rand.Read(id)
	require.NoError(t, err)

	private := []pkcs11.Attribute{
		attr(pkcs11.AttrClass, pkcs11.ULong(pkcs11.ClassPrivateKey)),
		attr(pkcs11.AttrToken, ckTrue),
		attr(attrPrivate, ckTrue),
		attr(attrSensitive, ckTrue),
		attr(attrSign, ckTrue),
		attr(pkcs11.AttrLabel, []byte(label)),
		attr(pkcs11.AttrID, id),
	}
	_, err = session.CreateObject(append(private, privateKeyAttributes(t, key)...)...)
	require.NoError(t, err, "import private key")

	public := []pkcs11.Attribute{
		attr(pkcs11.AttrClass, pkcs11.ULong(pkcs11.ClassPublicKey)),
		attr(pkcs11.AttrToken, ckTrue),
		attr(attrPrivate, ckFalse),
		attr(attrVerify, ckTrue),
		attr(pkcs11.AttrLabel, []byte(label)),
		attr(pkcs11.AttrID, id),
	}
	_, err = session.CreateObject(append(public, publicKeyAttributes(t, key)...)...)
	require.NoError(t, err, "import public key")
	return id
}

func importCertificate(t *testing.T, uri string, leaf *x509.Certificate, id []byte) {
	t.Helper()
	session := readWriteSession(t, uri)
	defer session.Close()

	serial, err := asn1.Marshal(leaf.SerialNumber)
	require.NoError(t, err)
	_, err = session.CreateObject(
		attr(pkcs11.AttrClass, pkcs11.ULong(pkcs11.ClassCertificate)),
		attr(pkcs11.AttrCertificateType, pkcs11.ULong(pkcs11.CertificateX509)),
		attr(pkcs11.AttrToken, ckTrue),
		attr(attrPrivate, ckFalse),
		attr(pkcs11.AttrLabel, []byte(leaf.Subject.CommonName)),
		attr(pkcs11.AttrID, id),
		attr(pkcs11.AttrSubject, leaf.RawSubject),
		attr(attrIssuer, leaf.RawIssuer),
		attr(attrSerialNumber, serial),
		attr(pkcs11.AttrValue, leaf.Raw),
	)
	require.NoError(t, err, "import certificate")
}

func readWriteSession(t *testing.T, uri string) *pkcs11.Session {
	t.Helper()
	parsed, err := pkcs11.ParseURI(uri)
	require.NoError(t, err)
	module, err := pkcs11.Load(parsed.Module())
	require.NoError(t, err)
	pin, err := parsed.PIN()
	require.NoError(t, err)
	session, err := module.OpenReadWriteSession(parsed.Token, pin)
	require.NoError(t, err)
	return session
}

func privateKeyAttributes(t *testing.T, key crypto.Signer) []pkcs11.Attribute {
	t.Helper()
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return []pkcs11.Attribute{
			attr(pkcs11.AttrKeyType, pkcs11.ULong(pkcs11.KeyEC)),
			attr(pkcs11.AttrECParams, oidP256),
			attr(pkcs11.AttrValue, k.D.FillBytes(make([]byte, 32))),
		}
	case *rsa.PrivateKey:
		k.Precompute()
		return []pkcs11.Attribute{
			attr(pkcs11.AttrKeyType, pkcs11.ULong(pkcs11.KeyRSA)),
			attr(pkcs11.AttrModulus, k.N.Bytes()),
			attr(pkcs11.AttrPublicExponent, big.NewInt(int64(k.E)).Bytes()),
			attr(attrPrivateExponent, k.D.Bytes()),
			attr(attrPrime1, k.Primes[0].Bytes()),
			attr(attrPrime2, k.Primes[1].Bytes()),
			attr(attrExponent1, k.Precomputed.Dp.Bytes()),
			attr(attrExponent2, k.Precomputed.Dq.Bytes()),
			attr(attrCoefficient, k.Precomputed.Qinv.Bytes()),
		}
	}
	t.Fatalf("unsupported key %T", key)
	return nil
}

// publicKeyAttributes describes the CKO_PUBLIC_KEY object tokens keep next to a private
// key, which is what the store reads to pair a certificate file with its key.
func publicKeyAttributes(t *testing.T, key crypto.Signer) []pkcs11.Attribute {
	t.Helper()
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		point := append([]byte{4}, k.X.FillBytes(make([]byte, 32))...)
		point = append(point, k.Y.FillBytes(make([]byte, 32))...)
		wrapped, err := asn1.Marshal(point)
		require.NoError(t, err)
		return []pkcs11.Attribute{
			attr(pkcs11.AttrKeyType, pkcs11.ULong(pkcs11.KeyEC)),
			attr(pkcs11.AttrECParams, oidP256),
			attr(pkcs11.AttrECPoint, wrapped),
		}
	case *rsa.PrivateKey:
		return []pkcs11.Attribute{
			attr(pkcs11.AttrKeyType, pkcs11.ULong(pkcs11.KeyRSA)),
			attr(pkcs11.AttrModulus, k.N.Bytes()),
			attr(pkcs11.AttrPublicExponent, big.NewInt(int64(k.E)).Bytes()),
		}
	}
	t.Fatalf("unsupported key %T", key)
	return nil
}

func attr(typ uint, value []byte) pkcs11.Attribute {
	return pkcs11.Attribute{Type: typ, Value: value}
}

// pkcs11TestStore builds the store for the token NB_TEST_PKCS11_URI names, skipping when
// no token is configured or this build lacks PKCS#11 support.
func pkcs11TestStore(t *testing.T, certDir string) (*PKCS11Store, string) {
	t.Helper()
	uri := os.Getenv(testPKCS11URIEnv)
	if uri == "" {
		t.Skipf("set %s to a PKCS#11 URI with a PIN to run", testPKCS11URIEnv)
	}
	store, err := NewPKCS11Store(PKCS11Config{URI: uri}, certDir)
	require.NoError(t, err)
	if _, err := pkcs11.Load(store.uri.Module()); errors.Is(err, pkcs11.ErrUnsupported) {
		t.Skip(err)
	}
	return store, uri
}

// TestCollect_PKCS11KeyWithFileCertificate covers the split layout: the key lives on the
// token, the certificate is a PEM file in the directory, and the two are paired by public
// key because nothing on the token carries the certificate's CKA_ID.
func TestCollect_PKCS11KeyWithFileCertificate(t *testing.T) {
	dir := t.TempDir()
	store, uri := pkcs11TestStore(t, dir)

	keys := map[string]crypto.Signer{"ecdsa": certtest.ECDSAKey(t), "rsa": certtest.RSAKey(t)}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			ca := certtest.NewCA(t, "corp-file-"+name)
			leaf := ca.Issue(t, key, "device-file-"+name)
			importKey(t, uri, key, "device-file-"+name)
			writeFile(t, dir, "device-"+name+".pem", certtest.CertPEM(leaf))

			challenger := certposture.NewChallenger([]byte("secret"))
			now := time.Now()
			nonce := challenger.Nonce(peerKey, now)
			checks := []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{Nonce: nonce, CaCertificates: []string{ca.PEM}}}}

			proofs := Collect(context.Background(), store, checks, peerKey)
			require.Len(t, proofs, 1, "the token key must prove the certificate kept on disk")
			chain, err := challenger.Verify(proofs[0], peerKey, now)
			require.NoError(t, err)
			assert.True(t, leaf.Equal(chain[0]), "proof must carry the certificate from the directory")
		})
	}
}

func TestPKCS11Store_FileChains(t *testing.T) {
	ca := certtest.NewCA(t, "corp")
	dir := t.TempDir()
	// Only certificate files without a key of their own belong to the token; the file
	// store answers for the others, and non-certificate files are ignored.
	writeFile(t, dir, "device.pem", certtest.CertPEM(ca.Issue(t, certtest.ECDSAKey(t), "device")))
	writeFile(t, dir, "ca.crt", ca.PEM)
	keyed := certtest.ECDSAKey(t)
	writeFile(t, dir, "inline.pem", certtest.CertPEM(ca.Issue(t, keyed, "inline"))+certtest.KeyPEM(t, keyed))
	writeFile(t, dir, "sibling.crt", certtest.CertPEM(ca.Issue(t, keyed, "sibling")))
	writeFile(t, dir, "sibling.key", certtest.KeyPEM(t, keyed))
	writeFile(t, dir, "notes.txt", "not a certificate")

	chains, err := (&PKCS11Store{uri: &pkcs11.URI{}, certDir: dir}).fileChains()
	require.NoError(t, err)
	var subjects []string
	for _, chain := range chains {
		subjects = append(subjects, chain[0].Subject.CommonName)
	}
	assert.ElementsMatch(t, []string{"device", "corp"}, subjects, "only key-less certificate files are left to the token")

	chains, err = (&PKCS11Store{uri: &pkcs11.URI{}}).fileChains()
	require.NoError(t, err)
	assert.Empty(t, chains, "no directory configured means no file certificates")
}

func TestNewPKCS11Store_PIN(t *testing.T) {
	tests := []struct {
		name       string
		cfg        PKCS11Config
		wantPIN    []byte
		wantModule string
	}{
		{"pin alone opens the first p11-kit token", PKCS11Config{PIN: "1234"}, []byte("1234"), pkcs11.DefaultModule},
		{"pin field wins over pin-value", PKCS11Config{URI: "pkcs11:?module-path=/lib/x.so&pin-value=0000", PIN: "1234"}, []byte("1234"), "/lib/x.so"},
		{"uri pin-value stands in for a missing field", PKCS11Config{URI: "pkcs11:?pin-value=0000"}, []byte("0000"), pkcs11.DefaultModule},
		{"no pin at all means no login", PKCS11Config{URI: "pkcs11:token=netbird"}, nil, pkcs11.DefaultModule},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewPKCS11Store(tt.cfg, "")
			require.NoError(t, err)
			pin, err := store.userPIN()
			require.NoError(t, err)
			assert.Equal(t, tt.wantPIN, pin, "PIN, nil meaning no login")
			assert.Equal(t, tt.wantModule, store.uri.Module(), "module to load")
		})
	}

	_, err := NewPKCS11Store(PKCS11Config{URI: "not-a-pkcs11-uri", PIN: "1234"}, "")
	assert.Error(t, err, "a malformed URI must not be silently replaced by the defaults")
}
