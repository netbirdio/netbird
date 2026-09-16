package tpm

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"go.step.sm/crypto/tpm/tss2"
)

// KeyPEMType is the PEM block type of a TPM 2.0 key file as defined by
// draft-bottomley-tpm2-keys and written by tpm2-openssl and tpm2-tss-engine.
const KeyPEMType = "TSS2 PRIVATE KEY"

var ErrKeyNeedsAuth = errors.New("TPM key requires an authorization value")

// ParseKey reads a TSS2 key file and returns a signer that produces every signature
// inside the TPM; only the digest goes in and only the signature comes out. A key with
// a persistent parent is loaded under it, a key whose parent is a hierarchy under the
// TCG default ECC primary that tpm2-openssl and tpm2-tss-engine derive as well. Keys
// guarded by an authorization value are rejected, since nothing can supply it without
// prompting.
func ParseKey(der []byte) (crypto.Signer, error) {
	key, err := tss2.ParsePrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse TSS2 key: %w", err)
	}
	if !key.EmptyAuth {
		return nil, ErrKeyNeedsAuth
	}
	public, err := key.Public()
	if err != nil {
		return nil, fmt.Errorf("decode TSS2 public key: %w", err)
	}
	return &keySigner{key: key, public: public}, nil
}

type keySigner struct {
	key    *tss2.TPMKey
	public crypto.PublicKey
}

func (s *keySigner) Public() crypto.PublicKey {
	return s.public
}

func (s *keySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	rwc, err := Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rwc.Close() }()

	signer, err := tss2.CreateSigner(rwc, s.key)
	if err != nil {
		return nil, fmt.Errorf("load TSS2 key: %w", err)
	}
	signer.SetSRKTemplate(tss2.ECCSRKTemplate)
	return signer.Sign(rand, digest, opts)
}
