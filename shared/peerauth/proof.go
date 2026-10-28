package peerauth

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	ServiceRelay  Service = 1
	ServiceSignal Service = 2
)

const proofContext = "netbird-peer-auth-proof-v1"

var (
	ErrBadProofSig   = errors.New("invalid proof signature")
	ErrStaleProof    = errors.New("proof timestamp outside the allowed skew")
	ErrHostMismatch  = errors.New("proof hostname is not one of the verifier hostnames")
	ErrMalformedHost = errors.New("malformed hostname")
)

// Service separates Relay proofs from Signal proofs, so one cannot be replayed as the other.
type Service byte

// Proof is the peer's signature over the token, the time and the hostname it dialed.
type Proof struct {
	Timestamp time.Time
	Hostname  string
	Signature []byte
}

// SignProof signs the token for one connection to the named verifier.
func SignProof(priv ed25519.PrivateKey, svc Service, token []byte, hostname string, now time.Time) (Proof, error) {
	host, err := NormalizeHostname(hostname)
	if err != nil {
		return Proof{}, err
	}
	ts := time.Unix(now.Unix(), 0)
	msg, err := proofSignedMessage(svc, token, ts, host)
	if err != nil {
		return Proof{}, err
	}
	return Proof{Timestamp: ts, Hostname: host, Signature: ed25519.Sign(priv, msg)}, nil
}

// VerifyProof checks the proof against the signing key from a verified token. An empty
// hostnames list skips the hostname check, which still leaves the signature bound to the name.
func VerifyProof(authPub ed25519.PublicKey, svc Service, token []byte, p Proof, hostnames []string, now time.Time, skew time.Duration) error {
	if d := now.Sub(p.Timestamp); d > skew || d < -skew {
		return ErrStaleProof
	}
	host, err := NormalizeHostname(p.Hostname)
	if err != nil || host != p.Hostname {
		return ErrMalformedHost
	}
	if len(hostnames) > 0 && !containsHost(hostnames, host) {
		return fmt.Errorf("%s: %w", host, ErrHostMismatch)
	}
	msg, err := proofSignedMessage(svc, token, p.Timestamp, host)
	if err != nil {
		return err
	}
	if !ed25519.Verify(authPub, msg, p.Signature) {
		return ErrBadProofSig
	}
	return nil
}

// NormalizeHostname reduces a dialed host, as url.URL.Hostname returns it, to the form both
// sides sign: lower case, no trailing dot.
func NormalizeHostname(host string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" || len(h) > math.MaxUint8 || strings.ContainsAny(h, "/[] ") {
		return "", fmt.Errorf("%q: %w", host, ErrMalformedHost)
	}
	return h, nil
}

func containsHost(hostnames []string, host string) bool {
	for _, h := range hostnames {
		if n, err := NormalizeHostname(h); err == nil && n == host {
			return true
		}
	}
	return false
}

func proofSignedMessage(svc Service, token []byte, ts time.Time, host string) ([]byte, error) {
	if len(token) > math.MaxUint16 {
		return nil, ErrMalformedToken
	}
	msg := make([]byte, 0, len(proofContext)+1+2+len(token)+8+1+len(host))
	msg = append(msg, proofContext...)
	msg = append(msg, byte(svc))
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(token)))
	msg = append(msg, token...)
	msg = binary.BigEndian.AppendUint64(msg, uint64(ts.Unix()))
	msg = append(msg, byte(len(host)))
	return append(msg, host...), nil
}
