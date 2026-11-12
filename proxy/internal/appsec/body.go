package appsec

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// bufferBody reads up to limit+1 bytes from r.Body and always restores r.Body so
// the request stays forwardable. oversize reports that the body exceeded limit, in
// which case the returned prefix must not be used for inspection: the bytes are
// only read so they can be replayed to the backend.
func bufferBody(r *http.Request, limit int64) (body []byte, oversize bool, err error) {
	original := r.Body
	buf, readErr := io.ReadAll(io.LimitReader(original, limit+1))
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		// Restore what was read so a downstream retry sees a consistent stream,
		// then surface the failure.
		r.Body = replay(buf, original)
		return nil, false, readErr
	}

	if int64(len(buf)) > limit {
		r.Body = replay(buf, original)
		return nil, true, nil
	}

	// The whole body is buffered, so the original is drained and can be closed.
	// A close error on a drained read-only body does not invalidate the bytes.
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	// Framing is deliberately left as the client sent it. Rewriting a chunked
	// request to a fixed Content-Length here would be invisible to the client
	// but not to the rest of the chain: a later body capture with a smaller cap
	// sees a known length over its cap and skips capture entirely, where an
	// unknown length would have given it a truncated prefix. Inspecting a
	// request must not change what any other layer gets to inspect.
	return buf, false, nil
}

// replay returns a ReadCloser that yields the already-read prefix followed by
// the remainder of the original stream, and closes the original.
func replay(prefix []byte, rest io.ReadCloser) io.ReadCloser {
	return struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(bytes.NewReader(prefix), rest),
		Closer: rest,
	}
}

// redactedPlaceholder replaces a credential value in the mirrored body. It is
// inert for rule matching, and its fixed length leaks nothing about the secret.
const redactedPlaceholder = "redacted"

// redactFormFields returns the body to mirror for a URL-encoded form, with the
// values of the named fields replaced. The proxy's own password / PIN login
// form posts to the service path itself, so without this the plaintext
// credential would reach the Security Engine.
//
// Only the credential values are removed, never the whole body: dropping the
// body outright would let a caller exempt any payload from inspection just by
// appending a field named "password". Everything else in the form stays
// inspectable, which is the point.
//
// Returns body unchanged when it is not a URL-encoded form or carries none of
// the fields.
//
// Substitution happens on the raw bytes rather than by re-encoding parsed
// values. Re-encoding would drop pairs that url.ParseQuery rejects, so a
// payload hidden in a malformed pair alongside a credential-named field would
// never be inspected while a tolerant backend parser still acted on it. Working
// byte-wise also avoids reordering keys and normalizing escapes, so the engine
// sees the same bytes the backend will.
//
// Field names match case-sensitively, on purpose: the caller passes the exact
// names the login handler reads via r.FormValue, and that lookup is itself
// case-sensitive. A "Password" field is therefore never a credential as far as
// the proxy is concerned, and redacting it would only blind the WAF to a value
// the proxy does not own.
func redactFormFields(contentType string, body []byte, fields []string) []byte {
	if len(fields) == 0 || len(body) == 0 {
		return body
	}
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "application/x-www-form-urlencoded" {
		return body
	}
	return redactURLEncoded(body, fields)
}

// redactURLEncoded replaces the values of the named keys in a URL-encoded
// key/value sequence, the shared syntax of a query string and a form body.
func redactURLEncoded(raw []byte, fields []string) []byte {
	// Split on "&" only, matching how Go's form parser delimits pairs.
	segments := bytes.Split(raw, []byte("&"))
	redacted := false
	for i, segment := range segments {
		rawKey, _, hasValue := bytes.Cut(segment, []byte("="))
		if !hasValue {
			continue
		}
		// Compare the decoded name, so an escaped spelling of the field
		// ("pass%77ord") is redacted too: the reader decodes before looking it
		// up. A key that fails to decode never reaches that reader either,
		// since the parser drops the pair.
		name, err := url.QueryUnescape(string(rawKey))
		if err != nil || !slices.Contains(fields, name) {
			continue
		}
		// Keep the key bytes as sent and replace only the value. Assigning a
		// fresh slice leaves raw untouched, which matters: the caller restored
		// the request body from the same buffer.
		segments[i] = []byte(string(rawKey) + "=" + redactedPlaceholder)
		redacted = true
	}
	if !redacted {
		return raw
	}
	return bytes.Join(segments, []byte("&"))
}

// redactQuery replaces the values of the named query parameters in a raw query
// string, leaving every other byte as sent.
func redactQuery(rawQuery string, params []string) string {
	if len(params) == 0 || rawQuery == "" {
		return rawQuery
	}
	return string(redactURLEncoded([]byte(rawQuery), params))
}

// redactCookieHeader replaces the values of the named cookies in a Cookie
// header, keeping the others intact: cookies are a zone WAF rules match on, so
// dropping the whole header would cost real coverage.
func redactCookieHeader(value string, names []string) string {
	if len(names) == 0 || value == "" {
		return value
	}
	parts := strings.Split(value, ";")
	redacted := false
	for i, part := range parts {
		name, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			continue
		}
		// Cookie names are case-sensitive and are not percent-decoded.
		if !slices.Contains(names, strings.TrimSpace(name)) {
			continue
		}
		parts[i] = name + "=" + redactedPlaceholder
		redacted = true
	}
	if !redacted {
		return value
	}
	return strings.Join(parts, ";")
}
