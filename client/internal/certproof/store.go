package certproof

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/tpm"
)

const (
	StoreDirEnv     = "NB_CERT_STORE_DIR"
	defaultStoreDir = "/etc/netbird/certs"
)

// errKeyMismatch rejects a key that does not belong to the certificate it sits with: it
// would sign a proof management can only reject, in place of a usable later candidate.
var errKeyMismatch = errors.New("private key does not match the certificate")

// Candidate is a certificate chain the peer can sign for. Signer never exposes the key.
// Chain is leaf first. Intermediates holds every other certificate the store has, so a
// path to a challenge's CAs can be found even where Chain followed a different issuer,
// such as an expired copy of a renewed intermediate.
type Candidate struct {
	Chain         []*x509.Certificate
	Signer        crypto.Signer
	Intermediates []*x509.Certificate
}

// issuers is every certificate other than the leaf that a path may run through.
func (c Candidate) issuers() []*x509.Certificate {
	return append(slices.Clip(c.Chain[1:]), c.Intermediates...)
}

// Store yields the certificates a peer may prove possession of. FileStore is the PEM
// directory implementation; OS keystores (CNG, Keychain, PKCS#11) slot in here.
type Store interface {
	Candidates(ctx context.Context) ([]Candidate, error)
}

// Config selects where the daemon looks for certificates. Dir is the Linux PEM directory,
// empty for NB_CERT_STORE_DIR or /etc/netbird/certs, and PKCS11 names a token whose keys
// sign for certificates on the token or in that directory.
//
// ProfileOwner is the OS account the active profile belongs to. On macOS and Windows only
// that account's certificate store is consulted for user certificates, so on a machine
// with several people signed in the result does not depend on who else is logged in.
// Empty means the profile has no owner, and only the user at the physical console counts.
type Config struct {
	Dir          string
	PKCS11       PKCS11Config
	ProfileOwner string
}

func (c Config) dir() string {
	if c.Dir != "" {
		return c.Dir
	}
	return StoreDir()
}

// FileStore reads PEM files from a directory. A file holds the chain (leaf first) and
// either its private key or a sibling "<name>.key" file holds it. The key is a plain
// PKCS#8, EC or RSA key, or a TSS2 key the TPM signs with.
type FileStore struct {
	dir string
}

func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
}

func StoreDir() string {
	if dir := os.Getenv(StoreDirEnv); dir != "" {
		return dir
	}
	return defaultStoreDir
}

func (s *FileStore) Candidates(_ context.Context) ([]Candidate, error) {
	paths, err := certFiles(s.dir)
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, path := range paths {
		chain, signer, err := loadPEM(path)
		if err != nil {
			log.Warnf("skipping certificate %s: %v", path, err)
			continue
		}
		if signer == nil {
			log.Debugf("certificate %s has no key file, only a token can sign for it", path)
			continue
		}
		candidates = append(candidates, Candidate{Chain: chain, Signer: signer})
	}
	return candidates, nil
}

// certFiles lists the certificate files in dir, none when the directory does not exist.
func certFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate store %s: %w", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && isCertFile(entry.Name()) {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, nil
}

// loadPEM reads a certificate file and its private key, held in the file itself or in
// the sibling "<name>.key" file. The signer is nil when neither holds a key.
func loadPEM(path string) ([]*x509.Certificate, crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	chain, signer, err := parsePEM(data)
	if err != nil {
		return nil, nil, err
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("no certificate")
	}
	if signer == nil {
		if signer, err = siblingKey(path); err != nil {
			return nil, nil, err
		}
		if signer == nil {
			return chain, nil, nil
		}
	}
	if !samePublicKey(signer.Public(), chain[0].PublicKey) {
		return nil, nil, errKeyMismatch
	}
	return chain, signer, nil
}

// siblingKey reads the private key from the "<name>.key" file next to a certificate
// file, or returns nil when there is no such file.
func siblingKey(path string) (crypto.Signer, error) {
	keyData, err := os.ReadFile(strings.TrimSuffix(path, filepath.Ext(path)) + ".key")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	_, signer, err := parsePEM(keyData)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("no private key in key file")
	}
	return signer, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	equaler, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && equaler.Equal(b)
}

func parsePEM(data []byte) ([]*x509.Certificate, crypto.Signer, error) {
	var chain []*x509.Certificate
	var signer crypto.Signer
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return chain, signer, nil
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse certificate: %w", err)
			}
			chain = append(chain, cert)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY", tpm.KeyPEMType:
			key, err := parsePrivateKey(block)
			if err != nil {
				return nil, nil, err
			}
			signer = key
		}
	}
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	var key any
	var err error
	switch block.Type {
	case tpm.KeyPEMType:
		return tpm.ParseKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key cannot sign")
	}
	return signer, nil
}

func isCertFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".crt", ".cer":
		return true
	}
	return false
}

// Stores queries several stores and carries on when one fails, so a broken token cannot
// hide the certificates a directory holds. A failure is logged instead of returned
// because Collect treats a store error as "no proofs at all".
type Stores []Store

func (s Stores) Candidates(ctx context.Context) ([]Candidate, error) {
	var all []Candidate
	for _, store := range s {
		candidates, err := store.Candidates(ctx)
		if err != nil {
			log.Warnf("certificate store %T unavailable: %v", store, err)
			continue
		}
		all = append(all, candidates...)
	}
	return all, nil
}
