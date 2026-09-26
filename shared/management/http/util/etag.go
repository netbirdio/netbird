package util

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	etagHeader    = "ETag"
	ifMatchHeader = "If-Match"

	// matchAny is the If-Match value that matches any current representation
	// of the resource (RFC 9110 §13.1.1).
	matchAny = "*"

	// weakPrefix marks a weak validator. If-Match is defined in terms of the
	// strong comparison function, under which a weak validator never matches.
	weakPrefix = "W/"
)

// SetETag writes etag as a strong ETag response header, quoted per RFC 9110.
// The value passed in is the bare validator — callers derive it (typically
// from the type being served) and this applies the wire syntax, so the quoting
// is decided in one place rather than at every handler.
//
// Call it before writing the body: once the response is committed the header
// no longer reaches the client. An empty etag writes no header at all, so a
// caller with nothing to validate against does not have to special-case it.
func SetETag(w http.ResponseWriter, etag string) {
	if etag == "" {
		return
	}
	w.Header().Set(etagHeader, strconv.Quote(etag))
}

// Precondition is a parsed If-Match request precondition. The zero value
// matches nothing; a nil *Precondition is an unconditional request and matches
// everything, so a handler can pass the result of IfMatch straight through
// without a presence check.
type Precondition struct {
	// tags are the strong entity-tags the client will accept, unquoted.
	tags []string

	// any records the "*" form, which matches any current representation.
	any bool
}

// IfMatch parses the request's If-Match precondition. It returns nil when the
// header is absent — an unconditional request, which is the back-compatible
// default: clients that know nothing of conditional requests keep working.
//
// A header that is present but carries nothing usable — empty, or nothing but
// weak validators — yields a precondition that matches nothing rather than
// nil. Failing closed is the only safe direction: a client that meant to send
// a precondition must not have it silently dropped and its write let through
// unguarded.
func IfMatch(r *http.Request) *Precondition {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		return nil
	}

	p := &Precondition{}
	for _, value := range values {
		for raw := range strings.SplitSeq(value, ",") {
			candidate := strings.TrimSpace(raw)
			switch {
			case candidate == "":
				// Tolerated rather than rejected: a stray comma changes
				// nothing about what the client is willing to accept.
			case candidate == matchAny:
				p.any = true
			case strings.HasPrefix(candidate, weakPrefix):
				// Dropped, not unwrapped. If-Match uses strong comparison, so
				// a weak validator cannot satisfy it — and unwrapping one into
				// a strong tag would quietly grant the match the client's own
				// header said it could not have.
			default:
				p.tags = append(p.tags, strings.Trim(candidate, `"`))
			}
		}
	}
	return p
}

// Matches reports whether etag — the bare validator of the resource as it
// currently stands — satisfies the precondition. A nil precondition matches
// everything.
//
// Callers must establish that the resource exists before consulting this: the
// "*" form asks whether there is any current representation, a question only
// the caller can answer, and this reports true for it.
func (p *Precondition) Matches(etag string) bool {
	if p == nil {
		return true
	}
	if p.any {
		return true
	}
	return slices.Contains(p.tags, etag)
}
