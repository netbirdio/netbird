package tpm

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"

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

// tss2KeyASN1 is the ASN.1 container of draft-bottomley-tpm2-keys, the format
// tpm2-openssl, tpm2-tss-engine and tpm2_encodeobject write. PublicKey and PrivateKey
// hold TPM2B structures, so each is its own two-byte length followed by that many bytes.
//
// EmptyAuth is decoded raw: OpenSSL-based tools write BOOLEAN TRUE as 0x01, which BER
// allows but encoding/asn1 rejects, as it accepts only the DER form 0xff. Parent is an
// int64 so a persistent handle such as 0x81000001 still fits on 32-bit platforms.
type tss2KeyASN1 struct {
	Type       asn1.ObjectIdentifier
	EmptyAuth  asn1.RawValue   `asn1:"optional,explicit,tag:0"`
	Policy     []asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Secret     []byte          `asn1:"optional,explicit,tag:2"`
	AuthPolicy []asn1.RawValue `asn1:"optional,explicit,tag:3"`
	Parent     int64
	PublicKey  []byte
	PrivateKey []byte
}

// tss2Key is a decoded key file the client can ask the TPM to load.
type tss2Key struct {
	EmptyAuth  bool
	Parent     uint32
	PublicKey  []byte
	PrivateKey []byte
}

// parseTSS2 decodes a TSS2 key file and rejects everything this client cannot honour,
// so a key that parses here is one the TPM can be asked to load.
func parseTSS2(der []byte) (*tss2Key, error) {
	raw := new(tss2KeyASN1)
	rest, err := asn1.Unmarshal(der, raw)
	if err != nil {
		return nil, fmt.Errorf("parse TSS2 key: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("parse TSS2 key: %d trailing bytes", len(rest))
	}
	emptyAuth, err := berBoolean(raw.EmptyAuth)
	if err != nil {
		return nil, fmt.Errorf("parse TSS2 key emptyAuth: %w", err)
	}

	switch {
	case !raw.Type.Equal(oidLoadableKey):
		return nil, fmt.Errorf("%w: %s", errNotLoadable, raw.Type)
	case len(raw.Policy) > 0 || len(raw.AuthPolicy) > 0:
		return nil, errKeyHasPolicy
	case len(raw.Secret) > 0:
		return nil, errKeyHasSecret
	case raw.Parent < 0 || raw.Parent > math.MaxUint32 || !validParent(uint32(raw.Parent)):
		return nil, fmt.Errorf("%w: %d", errBadParent, raw.Parent)
	case !validTPM2B(raw.PublicKey) || !validTPM2B(raw.PrivateKey):
		return nil, errBadBlob
	}
	return &tss2Key{
		EmptyAuth:  emptyAuth,
		Parent:     uint32(raw.Parent),
		PublicKey:  raw.PublicKey,
		PrivateKey: raw.PrivateKey,
	}, nil
}

// berBoolean decodes an optional BOOLEAN, absent meaning false. Any non-zero content
// byte is true, as BER (X.690 section 8.2.2) allows and OpenSSL writes.
func berBoolean(v asn1.RawValue) (bool, error) {
	if len(v.FullBytes) == 0 {
		return false, nil
	}
	// The field is explicitly tagged, so v is the [0] wrapper and the BOOLEAN is inside it.
	if v.Class == asn1.ClassContextSpecific && v.IsCompound {
		var inner asn1.RawValue
		rest, err := asn1.Unmarshal(v.Bytes, &inner)
		if err != nil || len(rest) > 0 {
			return false, errors.New("malformed explicit tag")
		}
		v = inner
	}
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagBoolean || v.IsCompound || len(v.Bytes) != 1 {
		return false, errors.New("not a BOOLEAN")
	}
	return v.Bytes[0] != 0, nil
}

// blobs returns the public and private areas with their TPM2B length prefix removed,
// which is the form the load command takes them in.
func (k *tss2Key) blobs() (public, private []byte) {
	return k.PublicKey[2:], k.PrivateKey[2:]
}

// validParent accepts a persistent handle, under which the key was wrapped directly, or
// one of the four hierarchies, under which the key is wrapped by a primary the TPM
// re-derives from the hierarchy seed.
func validParent(parent uint32) bool {
	return persistentHandle(parent) ||
		parent == uint32(legacy.HandleOwner) ||
		parent == uint32(legacy.HandleNull) ||
		parent == uint32(legacy.HandleEndorsement) ||
		parent == uint32(legacy.HandlePlatform)
}

func persistentHandle(h uint32) bool {
	return h>>24 == uint32(legacy.HandleTypePersistent)
}

// validTPM2B reports whether b is a TPM2B structure: a two-byte big-endian length
// followed by exactly that many bytes.
func validTPM2B(b []byte) bool {
	return len(b) >= 2 && len(b)-2 == int(b[0])<<8+int(b[1])
}
