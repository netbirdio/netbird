package peerauth

import (
	"errors"
	"strconv"
	"time"

	"google.golang.org/grpc/metadata"
)

// DefaultSkew is how far a proof timestamp may be from the verifier clock.
const DefaultSkew = 10 * time.Minute

var (
	ErrMissingCredentials   = errors.New("missing peer auth credentials")
	ErrMalformedCredentials = errors.New("malformed peer auth credentials")
)

// Verifier checks a peer's token and proof.
type Verifier struct {
	Service   Service
	Keys      TokenKeys
	Hostnames []string
	Skew      time.Duration
}

// Verify returns the token content once both the token and the proof are valid. The caller
// still has to match the peer identity it was handed against Token.WGPub.
func (v *Verifier) Verify(token []byte, p Proof, now time.Time) (*Token, error) {
	t, err := VerifyToken(token, v.Keys, now)
	if err != nil {
		return nil, err
	}
	skew := v.Skew
	if skew == 0 {
		skew = DefaultSkew
	}
	if err := VerifyProof(t.AuthPub, v.Service, token, p, v.Hostnames, now, skew); err != nil {
		return nil, err
	}
	return t, nil
}

// FromMetadata extracts the token and the proof sent to Signal. ErrMissingCredentials means none
// was sent; partial or unparseable credentials are ErrMalformedCredentials and must be refused.
func FromMetadata(md metadata.MD) ([]byte, Proof, error) {
	token, ts, host, sig := first(md, MetadataToken), first(md, MetadataTimestamp), first(md, MetadataHostname), first(md, MetadataSignature)
	if token == "" && ts == "" && host == "" && sig == "" {
		return nil, Proof{}, ErrMissingCredentials
	}
	if token == "" || ts == "" || host == "" || sig == "" {
		return nil, Proof{}, ErrMalformedCredentials
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, Proof{}, ErrMalformedCredentials
	}
	return []byte(token), Proof{Timestamp: time.Unix(unix, 0), Hostname: host, Signature: []byte(sig)}, nil
}

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}
