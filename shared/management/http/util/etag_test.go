package util

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetETag covers the wire syntax: the bare validator goes in, a quoted
// strong entity-tag comes out. Handlers pass what the type derived, so the
// quoting has to happen here or every handler re-decides it.
func TestSetETag(t *testing.T) {
	rec := httptest.NewRecorder()
	SetETag(rec, "9f86d081884c7d65")

	assert.Equal(t, `"9f86d081884c7d65"`, rec.Header().Get("ETag"),
		"the validator must be emitted quoted")
}

// TestSetETagEmpty pins the no-op: a caller with nothing to validate against
// must not emit an empty entity-tag, which would be a validator that every
// later request could match.
func TestSetETagEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	SetETag(rec, "")

	assert.Empty(t, rec.Header().Values("ETag"), "an empty validator must write no header")
}

// TestSetETagRoundTrip closes the loop between the two halves of the helper:
// what SetETag emits is what IfMatch accepts back. A client echoing the header
// it was given must match, or conditional requests never succeed in practice.
func TestSetETagRoundTrip(t *testing.T) {
	const etag = "9f86d081884c7d65"

	rec := httptest.NewRecorder()
	SetETag(rec, etag)

	r := httptest.NewRequest(http.MethodPut, "/", nil)
	r.Header.Set("If-Match", rec.Header().Get("ETag"))

	assert.True(t, IfMatch(r).Matches(etag), "an echoed ETag header must satisfy the precondition")
}

// TestIfMatchAbsent pins the back-compatibility guarantee: a request with no
// If-Match is unconditional, and the nil precondition it yields matches
// anything so handlers need no presence check.
func TestIfMatchAbsent(t *testing.T) {
	p := IfMatch(httptest.NewRequest(http.MethodPut, "/", nil))

	require.Nil(t, p, "an absent header must yield no precondition")
	assert.True(t, p.Matches("9f86d081884c7d65"), "a nil precondition must match anything")
	assert.True(t, p.Matches(""), "a nil precondition must not depend on the validator")
}

// TestIfMatchParsing walks the header forms a client can send. The weak and
// unusable cases are the ones that matter: each must yield a precondition that
// exists and refuses, never one that is absent and waves the write through.
func TestIfMatchParsing(t *testing.T) {
	const current = "9f86d081884c7d65"

	cases := []struct {
		name   string
		header string
		match  bool
		reason string
	}{
		{
			name:   "quoted current validator",
			header: `"9f86d081884c7d65"`,
			match:  true,
			reason: "the ordinary conditional request must be honoured",
		},
		{
			name:   "unquoted current validator",
			header: "9f86d081884c7d65",
			match:  true,
			reason: "a client that omits the quoting means the same thing, and only an exact value can match",
		},
		{
			name:   "stale validator",
			header: `"0000000000000000"`,
			match:  false,
			reason: "a validator from an earlier read must not match",
		},
		{
			name:   "star",
			header: "*",
			match:  true,
			reason: "* matches any current representation",
		},
		{
			name:   "list containing the current validator",
			header: `"0000000000000000", "9f86d081884c7d65"`,
			match:  true,
			reason: "If-Match is a list; any member matching is a match",
		},
		{
			name:   "list of stale validators",
			header: `"0000000000000000", "1111111111111111"`,
			match:  false,
			reason: "a list none of whose members match must not match",
		},
		{
			name:   "surrounding whitespace",
			header: `  "9f86d081884c7d65"  `,
			match:  true,
			reason: "list whitespace is not part of the entity-tag",
		},
		{
			name:   "stray comma",
			header: `"9f86d081884c7d65", `,
			match:  true,
			reason: "an empty list element says nothing about what the client accepts",
		},
		{
			name:   "weak validator of the current representation",
			header: `W/"9f86d081884c7d65"`,
			match:  false,
			reason: "If-Match uses strong comparison, so a weak validator never satisfies it",
		},
		{
			name:   "weak validator alongside a strong one",
			header: `W/"0000000000000000", "9f86d081884c7d65"`,
			match:  true,
			reason: "dropping the weak member must not discard the rest of the list",
		},
		{
			name:   "empty header",
			header: "",
			match:  false,
			reason: "a precondition the server cannot make sense of must fail closed, not vanish",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/", nil)
			r.Header.Set("If-Match", tc.header)

			p := IfMatch(r)
			require.NotNil(t, p, "a header that was sent must yield a precondition: %s", tc.reason)
			assert.Equal(t, tc.match, p.Matches(current), tc.reason)
		})
	}
}

// TestIfMatchRepeatedHeader covers the same list split across header lines,
// which is semantically identical to the comma form and which a proxy is free
// to produce.
func TestIfMatchRepeatedHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/", nil)
	r.Header.Add("If-Match", `"0000000000000000"`)
	r.Header.Add("If-Match", `"9f86d081884c7d65"`)

	assert.True(t, IfMatch(r).Matches("9f86d081884c7d65"),
		"entity-tags split across header lines must be read as one list")
}
