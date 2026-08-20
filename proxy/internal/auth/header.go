package auth

import (
	"crypto/sha256"
	"net/http"
	"sync"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
)

// Header implements header-based authentication. The service mapping carries
// the argon2id hash of every value accepted for the header, so the proxy
// verifies the credential locally rather than round-tripping to management.
type Header struct {
	headerName string
	hashes     []string
	verified   *verifiedValues
}

// NewHeader creates a Header authentication scheme accepting any value whose
// argon2id hash appears in hashes. An empty hashes slice rejects every request
// carrying the header, so a mapping that arrived without its hashes fails
// closed instead of leaving the service unprotected.
func NewHeader(headerName string, hashes []string) Header {
	return Header{
		headerName: http.CanonicalHeaderKey(headerName),
		hashes:     hashes,
		verified:   &verifiedValues{seen: make(map[[32]byte]struct{}, len(hashes))},
	}
}

// Type returns auth.MethodHeader.
func (Header) Type() auth.Method {
	return auth.MethodHeader
}

// Authenticate satisfies Scheme. Header credentials are resolved by Verify
// before the scheme loop runs, so a request that reaches here never carries
// the header and there is no credential to prompt for.
func (Header) Authenticate(*http.Request) (string, string, error) {
	return "", "", nil
}

// Verify reports whether the request carries the configured header and, when
// it does, whether the value matches one of the service's hashes.
func (h Header) Verify(r *http.Request) (present, matched bool) {
	value := r.Header.Get(h.headerName)
	if value == "" {
		return false, false
	}

	digest := sha256.Sum256([]byte(value))
	if h.verified.has(digest) {
		return true, true
	}

	for _, hash := range h.hashes {
		if argon2id.Verify(value, hash) == nil {
			h.verified.add(digest)
			return true, true
		}
	}
	return true, false
}

// verifiedValues remembers which header values already passed argon2id
// verification. argon2id is deliberately expensive (19 MiB, two passes) and
// header credentials repeat on every request, so re-deriving per request would
// dominate the hot path. The set cannot outgrow the number of configured
// hashes, and a mapping update builds a fresh scheme with an empty set.
// Values are keyed by digest so the plaintext credential is not retained.
type verifiedValues struct {
	mu   sync.Mutex
	seen map[[32]byte]struct{}
}

func (v *verifiedValues) has(digest [32]byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.seen[digest]
	return ok
}

func (v *verifiedValues) add(digest [32]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen[digest] = struct{}{}
}
