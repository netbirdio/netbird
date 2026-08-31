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
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	StoreDirEnv     = "NB_CERT_STORE_DIR"
	defaultStoreDir = "/etc/netbird/certs"
)

// Candidate is a certificate chain the peer can sign for. Signer never exposes the key.
type Candidate struct {
	Chain  []*x509.Certificate
	Signer crypto.Signer
}

// Store yields the certificates a peer may prove possession of. FileStore is the PEM
// directory implementation; OS keystores (CNG, Keychain, PKCS#11) slot in here.
type Store interface {
	Candidates(ctx context.Context) ([]Candidate, error)
}

// FileStore reads PEM files from a directory. A file holds the chain (leaf first) and
// either its private key or a sibling "<name>.key" file holds it.
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
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate store %s: %w", s.dir, err)
	}

	var candidates []Candidate
	for _, entry := range entries {
		if entry.IsDir() || !isCertFile(entry.Name()) {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		candidate, err := s.load(path)
		if err != nil {
			log.Warnf("skipping certificate %s: %v", path, err)
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func (s *FileStore) load(path string) (Candidate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Candidate{}, err
	}
	chain, signer, err := parsePEM(data)
	if err != nil {
		return Candidate{}, err
	}
	if len(chain) == 0 {
		return Candidate{}, errors.New("no certificate")
	}
	if signer == nil {
		keyData, err := os.ReadFile(strings.TrimSuffix(path, filepath.Ext(path)) + ".key")
		if err != nil {
			return Candidate{}, fmt.Errorf("no private key: %w", err)
		}
		if _, signer, err = parsePEM(keyData); err != nil {
			return Candidate{}, err
		}
		if signer == nil {
			return Candidate{}, errors.New("no private key in key file")
		}
	}
	return Candidate{Chain: chain, Signer: signer}, nil
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
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
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
