package client

import (
	"crypto/ed25519"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/peerauth"
)

// proofRefreshInterval keeps one proof per window, so Signal can cache its verification. It
// stays well below peerauth.DefaultSkew.
const proofRefreshInterval = 5 * time.Minute

// authCredentials holds the auth token and the proof presented with it on every Signal call.
type authCredentials struct {
	mu       sync.Mutex
	key      ed25519.PrivateKey
	hostname string
	token    []byte
	proof    peerauth.Proof
}

// update replaces the auth token; an empty one means none, so Signal is called as by a legacy peer.
func (a *authCredentials) update(token []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = nil
	if len(token) > 0 {
		a.token = append([]byte(nil), token...)
	}
	a.proof = peerauth.Proof{}
}

// metadataPairs returns the token and a proof as gRPC metadata, or nil without an auth token.
func (a *authCredentials) metadataPairs(now time.Time) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == nil {
		return nil, nil
	}
	if a.key == nil {
		return nil, errors.New("auth token without auth key")
	}
	// A negative age means the clock stepped back: the cached proof would look stale to Signal.
	if age := now.Sub(a.proof.Timestamp); a.proof.Signature == nil || age < 0 || age >= proofRefreshInterval {
		proof, err := peerauth.SignProof(a.key, peerauth.ServiceSignal, a.token, a.hostname, now)
		if err != nil {
			return nil, err
		}
		a.proof = proof
	}
	return peerauth.MetadataPairs(a.token, a.proof), nil
}

// signalHostname returns the host part of the Signal address, which may carry a scheme and a port.
func signalHostname(addr string) string {
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil {
			return u.Hostname()
		}
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
