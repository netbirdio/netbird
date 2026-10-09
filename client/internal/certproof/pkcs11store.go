package certproof

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/pkcs11"
)

// PKCS11Config names the token whose certificates the store yields. URI is an RFC 7512
// PKCS#11 URI, or empty for the first token the p11-kit proxy exposes. PIN is the user
// PIN, and takes precedence over a pin-value or pin-source the URI carries.
type PKCS11Config struct {
	URI string
	PIN string
}

// PKCS11Store yields the identities of a PKCS#11 token, which is how tpm2-pkcs11 exposes
// TPM-held keys on Linux. Certificates on the token are paired with keys by CKA_ID, the
// convention tpm2_ptool addcert and pkcs11-tool follow; certificate files in the PEM
// directory by public key. Every signature happens on the token.
type PKCS11Store struct {
	uri     *pkcs11.URI
	pin     string
	certDir string
}

// NewPKCS11Store parses cfg.URI, standing in the bare defaults when it is empty. Files in
// certDir without a key of their own are paired with the token's keys by public key.
func NewPKCS11Store(cfg PKCS11Config, certDir string) (*PKCS11Store, error) {
	store := &PKCS11Store{uri: &pkcs11.URI{}, pin: cfg.PIN, certDir: certDir}
	if cfg.URI == "" {
		return store, nil
	}
	parsed, err := pkcs11.ParseURI(cfg.URI)
	if err != nil {
		return nil, err
	}
	store.uri = parsed
	return store, nil
}

func (s *PKCS11Store) Candidates(_ context.Context) ([]Candidate, error) {
	session, err := s.open()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	certs, err := tokenCertificates(session)
	if err != nil {
		return nil, err
	}
	fileChains, err := s.fileChains()
	if err != nil {
		return nil, err
	}
	log.Infof("%s holds %d certificates, %d certificate files without a key wait for its keys", s, len(certs), len(fileChains))

	pool := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		pool = append(pool, cert.cert)
	}
	for _, chain := range fileChains {
		pool = append(pool, chain...)
	}

	var candidates []Candidate
	for _, cert := range certs {
		if _, err := privateKey(session, cert.id); err != nil {
			log.Infof("%s certificate %q has no usable private key: %v", s, cert.cert.Subject, err)
			continue
		}
		candidates = append(candidates, s.candidate(cert.cert, cert.id, pool))
	}
	if len(fileChains) == 0 {
		return candidates, nil
	}

	keys, err := tokenPublicKeys(session)
	if err != nil {
		return nil, err
	}
	for _, chain := range fileChains {
		leaf := chain[0]
		id, ok := keys.idFor(leaf.PublicKey)
		if !ok {
			log.Debugf("%s holds no key for certificate %q from %s", s, leaf.Subject, s.certDir)
			continue
		}
		candidates = append(candidates, s.candidate(leaf, id, pool))
	}
	return candidates, nil
}

func (s *PKCS11Store) candidate(leaf *x509.Certificate, id []byte, pool []*x509.Certificate) Candidate {
	chain := buildChain(leaf, pool)
	log.Infof("%s candidate %q issued by %q built a chain of %d certificates", s, leaf.Subject, leaf.Issuer, len(chain))
	return Candidate{Chain: chain, Signer: &pkcs11Signer{store: s, leaf: leaf, id: id}}
}

// fileChains reads the certificate files in the PEM directory that carry no key of their
// own; the file store answers for the ones that do.
func (s *PKCS11Store) fileChains() ([][]*x509.Certificate, error) {
	if s.certDir == "" {
		return nil, nil
	}
	paths, err := certFiles(s.certDir)
	if err != nil {
		return nil, err
	}
	var chains [][]*x509.Certificate
	for _, path := range paths {
		chain, signer, err := loadPEM(path)
		if err != nil || signer != nil {
			continue
		}
		chains = append(chains, chain)
	}
	return chains, nil
}

type tokenKey struct {
	id     []byte
	public crypto.PublicKey
}

type tokenKeys []tokenKey

func tokenPublicKeys(session *pkcs11.Session) (tokenKeys, error) {
	objects, err := session.FindObjects(pkcs11.Attribute{Type: pkcs11.AttrClass, Value: pkcs11.ULong(pkcs11.ClassPublicKey)})
	if err != nil {
		return nil, err
	}
	keys := make(tokenKeys, 0, len(objects))
	for _, object := range objects {
		id, err := session.Attribute(object, pkcs11.AttrID)
		if err != nil {
			return nil, err
		}
		public, err := session.PublicKey(object)
		if err != nil {
			log.Debugf("skipping public key on PKCS#11 token: %v", err)
			continue
		}
		keys = append(keys, tokenKey{id: id, public: public})
	}
	return keys, nil
}

// idFor finds the token key whose public half is pub, so a certificate kept outside the
// token is still signed for by the key inside it.
func (k tokenKeys) idFor(pub crypto.PublicKey) ([]byte, bool) {
	for _, key := range k {
		equaler, ok := key.public.(interface{ Equal(crypto.PublicKey) bool })
		if ok && len(key.id) > 0 && equaler.Equal(pub) {
			return key.id, true
		}
	}
	return nil, false
}

func (s *PKCS11Store) String() string {
	if s.uri.Token == "" {
		return "PKCS#11 token"
	}
	return fmt.Sprintf("PKCS#11 token %q", s.uri.Token)
}

func (s *PKCS11Store) open() (*pkcs11.Session, error) {
	module, err := pkcs11.Load(s.uri.Module())
	if err != nil {
		return nil, err
	}
	pin, err := s.userPIN()
	if err != nil {
		return nil, err
	}
	return module.OpenSession(s.uri.Token, pin)
}

func (s *PKCS11Store) userPIN() ([]byte, error) {
	if s.pin != "" {
		return []byte(s.pin), nil
	}
	return s.uri.PIN()
}

type tokenCertificate struct {
	cert *x509.Certificate
	id   []byte
}

func tokenCertificates(session *pkcs11.Session) ([]tokenCertificate, error) {
	objects, err := session.FindObjects(
		pkcs11.Attribute{Type: pkcs11.AttrClass, Value: pkcs11.ULong(pkcs11.ClassCertificate)},
		pkcs11.Attribute{Type: pkcs11.AttrCertificateType, Value: pkcs11.ULong(pkcs11.CertificateX509)},
	)
	if err != nil {
		return nil, err
	}
	certs := make([]tokenCertificate, 0, len(objects))
	for _, object := range objects {
		der, err := session.Attribute(object, pkcs11.AttrValue)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Warnf("skipping unparsable certificate on PKCS#11 token: %v", err)
			continue
		}
		id, err := session.Attribute(object, pkcs11.AttrID)
		if err != nil {
			return nil, err
		}
		certs = append(certs, tokenCertificate{cert: cert, id: id})
	}
	return certs, nil
}

var errNoPrivateKey = errors.New("no private key shares the certificate's CKA_ID")

func privateKey(session *pkcs11.Session, id []byte) (pkcs11.Object, error) {
	if len(id) == 0 {
		return 0, errNoPrivateKey
	}
	keys, err := session.FindObjects(
		pkcs11.Attribute{Type: pkcs11.AttrClass, Value: pkcs11.ULong(pkcs11.ClassPrivateKey)},
		pkcs11.Attribute{Type: pkcs11.AttrID, Value: id},
	)
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, errNoPrivateKey
	}
	return keys[0], nil
}

// pkcs11Signer holds only the certificate and its CKA_ID; the key is looked up in a fresh
// session at signing time so no token handle outlives a call.
type pkcs11Signer struct {
	store *PKCS11Store
	leaf  *x509.Certificate
	id    []byte
}

func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.leaf.PublicKey
}

func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme, err := schemeFor(s.leaf.PublicKey, opts)
	if err != nil {
		return nil, err
	}
	session, err := s.store.open()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	key, err := privateKey(session, s.id)
	if err != nil {
		return nil, err
	}
	signature, err := session.Sign(pkcs11Mechanism(scheme), key, digest)
	if err != nil {
		return nil, err
	}
	if scheme == schemeRSAPSSSHA256 {
		return signature, nil
	}
	return ecdsaSignatureASN1(signature)
}

// pkcs11Mechanism maps a signature scheme onto the token mechanism that consumes a digest.
func pkcs11Mechanism(scheme sigScheme) pkcs11.Mechanism {
	if scheme == schemeRSAPSSSHA256 {
		return pkcs11.Mechanism{
			Type: pkcs11.MechRSAPKCSPSS,
			PSS:  &pkcs11.PSSParams{Hash: pkcs11.MechSHA256, MGF: pkcs11.MGF1SHA256, SaltLen: sha256.Size},
		}
	}
	return pkcs11.Mechanism{Type: pkcs11.MechECDSA}
}
