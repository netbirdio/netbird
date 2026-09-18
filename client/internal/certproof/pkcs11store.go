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

const PKCS11URIEnv = "NB_CERT_PKCS11_URI"

// PKCS11Store yields the identities of a PKCS#11 token, which is how tpm2-pkcs11 exposes
// TPM-held keys on Linux. Certificates and keys are paired by CKA_ID, the convention
// tpm2_ptool addcert and pkcs11-tool follow, and every signature happens on the token.
type PKCS11Store struct {
	uri *pkcs11.URI
}

// NewPKCS11Store reads the token, module and PIN source from an RFC 7512 PKCS#11 URI.
func NewPKCS11Store(uri string) (*PKCS11Store, error) {
	parsed, err := pkcs11.ParseURI(uri)
	if err != nil {
		return nil, err
	}
	return &PKCS11Store{uri: parsed}, nil
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
	log.Infof("%s holds %d certificates", s, len(certs))

	pool := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		pool = append(pool, cert.cert)
	}
	var candidates []Candidate
	for _, cert := range certs {
		if _, err := privateKey(session, cert.id); err != nil {
			log.Infof("%s certificate %q has no usable private key: %v", s, cert.cert.Subject, err)
			continue
		}
		chain := buildChain(cert.cert, pool)
		log.Infof("%s candidate %q issued by %q built a chain of %d certificates", s, cert.cert.Subject, cert.cert.Issuer, len(chain))
		candidates = append(candidates, Candidate{Chain: chain, Signer: &pkcs11Signer{store: s, leaf: cert.cert, id: cert.id}})
	}
	return candidates, nil
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
	pin, err := s.uri.PIN()
	if err != nil {
		return nil, err
	}
	return module.OpenSession(s.uri.Token, pin)
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
