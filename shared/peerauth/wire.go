package peerauth

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"time"
)

// gRPC metadata keys carrying the credentials to Signal. Keys ending in -bin are binary.
const (
	MetadataToken     = "x-netbird-auth-token-bin" //nolint:gosec // G101: metadata key name, not a credential
	MetadataTimestamp = "x-netbird-auth-ts"
	MetadataHostname  = "x-netbird-auth-host"
	MetadataSignature = "x-netbird-auth-sig-bin"
)

const (
	extTypeProof byte = 1

	sizeExtHeader = 1 + 2
	sizeTimestamp = 8
)

var (
	ErrNoProof            = errors.New("no proof in the auth extension")
	ErrMalformedExtension = errors.New("malformed auth extension")
)

// MarshalRelayExtension encodes the proof for the extension area of the Relay auth envelope as
// type-length-value entries, so later fields can be added without breaking older parsers.
func MarshalRelayExtension(p Proof) ([]byte, error) {
	valueLen := sizeTimestamp + len(p.Signature) + len(p.Hostname)
	if len(p.Signature) != ed25519.SignatureSize || valueLen > math.MaxUint16 {
		return nil, ErrMalformedExtension
	}
	buf := make([]byte, 0, sizeExtHeader+valueLen)
	buf = append(buf, extTypeProof)
	buf = binary.BigEndian.AppendUint16(buf, uint16(valueLen))
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.Timestamp.Unix()))
	buf = append(buf, p.Signature...)
	return append(buf, p.Hostname...), nil
}

// UnmarshalRelayExtension returns the proof from the extension area, skipping unknown entries.
// ErrNoProof means a legacy client; any other error means credentials that must be refused.
func UnmarshalRelayExtension(ext []byte) (Proof, error) {
	for len(ext) > 0 {
		if len(ext) < sizeExtHeader {
			return Proof{}, ErrMalformedExtension
		}
		typ := ext[0]
		n := int(binary.BigEndian.Uint16(ext[1:sizeExtHeader]))
		if len(ext) < sizeExtHeader+n {
			return Proof{}, ErrMalformedExtension
		}
		value := ext[sizeExtHeader : sizeExtHeader+n]
		ext = ext[sizeExtHeader+n:]
		if typ != extTypeProof {
			continue
		}
		if n < sizeTimestamp+ed25519.SignatureSize {
			return Proof{}, ErrMalformedExtension
		}
		return Proof{
			Timestamp: time.Unix(int64(binary.BigEndian.Uint64(value)), 0),
			Signature: value[sizeTimestamp : sizeTimestamp+ed25519.SignatureSize],
			Hostname:  string(value[sizeTimestamp+ed25519.SignatureSize:]),
		}, nil
	}
	return Proof{}, ErrNoProof
}

// MetadataPairs returns the gRPC metadata key-value pairs carrying the token and the proof.
func MetadataPairs(token []byte, p Proof) []string {
	return []string{
		MetadataToken, string(token),
		MetadataTimestamp, strconv.FormatInt(p.Timestamp.Unix(), 10),
		MetadataHostname, p.Hostname,
		MetadataSignature, string(p.Signature),
	}
}
