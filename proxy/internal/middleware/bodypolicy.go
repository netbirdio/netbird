package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ErrExpectContinue is returned when a middleware attempts to replace
// the body of a request that advertised Expect: 100-continue.
var ErrExpectContinue = errors.New("body replace rejected: request has Expect: 100-continue")

// ErrOriginalNotDrained is returned when the original body was not
// fully consumed before replacement. This prevents the backend from
// seeing a mix of original bytes and the replacement.
var ErrOriginalNotDrained = errors.New("body replace rejected: original body not drained")

// ErrContentLengthMismatch is returned when the client-advertised
// Content-Length disagrees with the number of bytes actually read from
// the body (short-read).
var ErrContentLengthMismatch = errors.New("body replace rejected: content-length mismatch (short read)")

// ValidateBodyReplace runs the smuggling-prevention rules before a
// body replacement is applied. Callers must pass originalDrained=true
// once they have read r.Body to EOF.
func ValidateBodyReplace(r *http.Request, newBody []byte, originalDrained bool) error {
	if r == nil {
		return errors.New("body replace rejected: nil request")
	}
	if strings.EqualFold(r.Header.Get("Expect"), "100-continue") {
		return ErrExpectContinue
	}
	if !originalDrained {
		return ErrOriginalNotDrained
	}
	if cl := r.Header.Get("Content-Length"); cl != "" && r.ContentLength > 0 {
		parsed, err := strconv.ParseInt(cl, 10, 64)
		if err == nil && parsed != r.ContentLength {
			return fmt.Errorf("%w: header=%d actual=%d", ErrContentLengthMismatch, parsed, r.ContentLength)
		}
	}
	return nil
}

// ApplyBodyReplace swaps r.Body for a reader over newBody, recomputes
// Content-Length, and strips Transfer-Encoding and Trailer so no stale
// framing reaches the backend.
func ApplyBodyReplace(r *http.Request, newBody []byte) {
	if r == nil {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Trailer")
	r.TransferEncoding = nil
	r.Trailer = nil
}
