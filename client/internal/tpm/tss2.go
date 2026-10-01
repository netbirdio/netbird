package tpm

import (
	"encoding/asn1"
	"errors"
	"fmt"

	legacy "github.com/google/go-tpm/legacy/tpm2"
)

// oidLoadableKey marks a key wrapped by a parent inside the TPM, which is the only kind
// enrollment tooling writes for a signing key and the only kind that can be loaded under
// an SRK. The sealed and importable variants carry different material and are refused.
var oidLoadableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

var (
	errNotLoadable  = errors.New("TSS2 key is not a loadable key")
	errKeyHasPolicy = errors.New("TSS2 key carries a policy, which is not supported")
	errKeyHasSecret = errors.New("TSS2 key carries a secret, which is not supported")
	errBadParent    = errors.New("TSS2 key names a parent that is neither persistent nor a hierarchy")
	errBadBlob      = errors.New("TSS2 key blob is malformed")
)

// tss2Key is the ASN.1 container of draft-bottomley-tpm2-keys, the format tpm2-openssl,
// tpm2-tss-engine and tpm2_encodeobject write. PublicKey and PrivateKey hold TPM2B
// structures, so each is its own two-byte length followed by that many bytes.
type tss2Key struct {
	Type       asn1.ObjectIdentifier
	EmptyAuth  bool            `asn1:"optional,explicit,tag:0"`
	Policy     []asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Secret     []byte          `asn1:"optional,explicit,tag:2"`
	AuthPolicy []asn1.RawValue `asn1:"optional,explicit,tag:3"`
	Parent     int
	PublicKey  []byte
	PrivateKey []byte
}

// parseTSS2 decodes a TSS2 key file and rejects everything this client cannot honour,
// so a key that parses here is one the TPM can be asked to load.
func parseTSS2(der []byte) (*tss2Key, error) {
	key := new(tss2Key)
	rest, err := asn1.Unmarshal(der, key)
	if err != nil {
		return nil, fmt.Errorf("parse TSS2 key: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("parse TSS2 key: %d trailing bytes", len(rest))
	}

	switch {
	case !key.Type.Equal(oidLoadableKey):
		return nil, fmt.Errorf("%w: %s", errNotLoadable, key.Type)
	case len(key.Policy) > 0 || len(key.AuthPolicy) > 0:
		return nil, errKeyHasPolicy
	case len(key.Secret) > 0:
		return nil, errKeyHasSecret
	case !validParent(key.Parent):
		return nil, fmt.Errorf("%w: %d", errBadParent, key.Parent)
	case !validTPM2B(key.PublicKey) || !validTPM2B(key.PrivateKey):
		return nil, errBadBlob
	}
	return key, nil
}

// blobs returns the public and private areas with their TPM2B length prefix removed,
// which is the form the load command takes them in.
func (k *tss2Key) blobs() (public, private []byte) {
	return k.PublicKey[2:], k.PrivateKey[2:]
}

// validParent accepts a persistent handle, under which the key was wrapped directly, or
// one of the four hierarchies, under which the key is wrapped by a primary the TPM
// re-derives from the hierarchy seed.
func validParent(parent int) bool {
	return persistentHandle(parent) ||
		parent == int(legacy.HandleOwner) ||
		parent == int(legacy.HandleNull) ||
		parent == int(legacy.HandleEndorsement) ||
		parent == int(legacy.HandlePlatform)
}

func persistentHandle(h int) bool {
	return h>>24 == int(legacy.HandleTypePersistent)
}

// validTPM2B reports whether b is a TPM2B structure: a two-byte big-endian length
// followed by exactly that many bytes.
func validTPM2B(b []byte) bool {
	return len(b) >= 2 && len(b)-2 == int(b[0])<<8+int(b[1])
}
