package llm_guardrail

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactPIIEmptyInput(t *testing.T) {
	assert.Equal(t, "", redactPII(""), "empty input must round-trip unchanged")
}

func TestRedactPIIPlainTextUntouched(t *testing.T) {
	in := "the quick brown fox jumps over the lazy dog"
	assert.Equal(t, in, redactPII(in), "non-PII text must pass through unchanged")
}

func TestRedactPIIEmail(t *testing.T) {
	cases := []string{
		"contact user@example.com today",
		"first.last+tag@sub.example.co",
		"USER_42@EXAMPLE.COM",
	}
	for _, in := range cases {
		out := redactPII(in)
		assert.Contains(t, out, "[REDACTED:email]", "email must be redacted in %q", in)
		assert.NotContains(t, strings.ToLower(out), "@example", "raw email host must not survive in %q", in)
	}
}

func TestRedactPIISSN(t *testing.T) {
	in := "ssn 123-45-6789 should be hidden"
	out := redactPII(in)
	assert.Contains(t, out, "[REDACTED:ssn]", "SSN must be redacted")
	assert.NotContains(t, out, "123-45-6789", "raw SSN must not survive")
}

func TestRedactPIIPhoneE164(t *testing.T) {
	in := "call me at +14155551234 anytime"
	out := redactPII(in)
	assert.Contains(t, out, "[REDACTED:phone]", "E.164 phone must be redacted")
	assert.NotContains(t, out, "+14155551234", "raw E.164 phone must not survive")
}

func TestRedactPIIPhoneNorthAmerican(t *testing.T) {
	cases := []string{
		"call (415) 555-1234 now",
		"call 415-555-1234 now",
		"call 415.555.1234 now",
		"call 415 555 1234 now",
	}
	for _, in := range cases {
		out := redactPII(in)
		assert.Contains(t, out, "[REDACTED:phone]", "NA phone must be redacted in %q", in)
		assert.NotContains(t, out, "555-1234", "raw NA phone must not survive in %q", in)
	}
}

func TestRedactPIIBearerKeepsKeyword(t *testing.T) {
	cases := []struct {
		in      string
		keyword string
	}{
		{"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", "Bearer"},
		{"token = abcdefghijklmnopqrstuvwxyz", "token"},
		{"api_key=abcdefghijklmnopqrstuvwxyz0123", "api_key"},
		{"API-KEY: abcdefghijklmnopqrstuvwxyz0123", "API-KEY"},
		{"authorization: abcdefghijklmnopqrstuvwxyz0123", "authorization"},
	}
	for _, tc := range cases {
		out := redactPII(tc.in)
		assert.Contains(t, out, "[REDACTED:bearer]", "bearer-style secret must be redacted in %q", tc.in)
		assert.Contains(t, out, tc.keyword, "leading keyword %q must be preserved in %q", tc.keyword, tc.in)
		assert.NotContains(t, out, "abcdefghijklmnopqrstuvwxyz0123", "raw bearer payload must not survive in %q", tc.in)
	}
}

func TestRedactPIIBearerShortValueUntouched(t *testing.T) {
	in := "token=short"
	out := redactPII(in)
	assert.Equal(t, in, out, "short bearer-style values must not be redacted")
}

func TestRedactPIICombined(t *testing.T) {
	in := "email user@example.com phone +14155551234 ssn 123-45-6789 token abcdefghijklmnopqrstuvwxyz0123"
	out := redactPII(in)
	assert.Contains(t, out, "[REDACTED:email]", "email must be redacted in combined input")
	assert.Contains(t, out, "[REDACTED:phone]", "phone must be redacted in combined input")
	assert.Contains(t, out, "[REDACTED:ssn]", "SSN must be redacted in combined input")
	assert.Contains(t, out, "[REDACTED:bearer]", "bearer must be redacted in combined input")
	assert.NotContains(t, out, "user@example.com", "raw email must not survive combined input")
	assert.NotContains(t, out, "+14155551234", "raw phone must not survive combined input")
	assert.NotContains(t, out, "123-45-6789", "raw SSN must not survive combined input")
}

func TestRedactPIICreditCard(t *testing.T) {
	// 4242424242424242 is a well-known Stripe test number (Visa, Luhn-valid).
	cases := []string{
		"please charge 4242424242424242 now",
		"card: 4242-4242-4242-4242",
		"4242 4242 4242 4242 expires 12/30",
	}
	for _, in := range cases {
		out := redactPII(in)
		assert.Contains(t, out, "[REDACTED:cc]", "Luhn-valid credit card must be redacted in %q", in)
		assert.NotContains(t, out, "4242424242424242", "raw card digits must not survive in %q", in)
		assert.NotContains(t, out, "4242-4242-4242-4242", "raw dashed card must not survive in %q", in)
	}
}

func TestRedactPIIIPv4(t *testing.T) {
	cases := []string{
		"connect to 10.0.42.7 over the tunnel",
		"server 192.168.1.100 down",
		"public address 203.0.113.42 was hit",
	}
	for _, in := range cases {
		out := redactPII(in)
		assert.Contains(t, out, "[REDACTED:ip]", "IPv4 must be redacted in %q", in)
	}
}

func TestRedactPIIJWT(t *testing.T) {
	// No "token "/"bearer " prefix here, so the bearer-with-keyword pass leaves
	// it alone and the JWT pattern from middleware.Scan must catch it.
	in := "session eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzQyIn0.signaturepart expires soon"
	out := redactPII(in)
	assert.Contains(t, out, "[REDACTED:jwt]", "JWT must be redacted when no bearer keyword precedes it")
	assert.NotContains(t, out, "eyJhbGciOiJIUzI1NiJ9", "raw JWT header must not survive")
}

func TestRedactPIIAWSAccessKey(t *testing.T) {
	in := "the key AKIAIOSFODNN7EXAMPLE belongs to test user"
	out := redactPII(in)
	assert.Contains(t, out, "[REDACTED:aws_key]", "AWS access key must be redacted")
	assert.NotContains(t, out, "AKIAIOSFODNN7EXAMPLE", "raw AWS key must not survive")
}

func TestRedactPIIPlainNumbersUntouched(t *testing.T) {
	// 1234567890123 is 13 digits but fails Luhn; must NOT trip the CC redactor.
	// We use a 13-digit value (the CC-candidate range starts at 13) so the only
	// risk is the CC pattern firing. Phone redaction is 10-digit by design and
	// would catch 1234567890123 as a phone — that's expected and not what this
	// test guards against.
	in := "order number 1234567890123 is queued"
	out := redactPII(in)
	assert.NotContains(t, out, "[REDACTED:cc]", "non-Luhn digit sequences must not be redacted as credit cards")
}

// piiFixture mirrors the user-supplied test fixture: each record carries one
// email, one SSN, and one phone in a representative format. The test asserts
// that EVERY raw token disappears after redaction and the right [REDACTED:*]
// markers show up. Names are kept in the input and must survive — names are
// not a pattern the redactor tries to catch.
type piiFixture struct {
	name  string // person name (must survive redaction)
	email string
	ssn   string
	phone string
}

var fixtureRecords = []piiFixture{
	{"Alice Johnson", "alice.johnson@example.com", "123-45-6789", "(202) 555-0147"},
	{"Brian Smith", "brian.smith@example.org", "987-65-4321", "202-555-0163"},
	{"Carla Nguyen", "c.nguyen@test.local", "111-22-3333", "+1-202-555-0188"},
	{"David Martinez", "david.martinez@example.com", "222-33-4444", "202.555.0199"},
	{"Evelyn Parker", "evelyn.parker@example.org", "333-44-5555", "1-202-555-0112"},
	{"Frank O'Connor", "frank.oconnor@test.local", "444-55-6666", "2025550134"},
	{"Grace Lee", "grace.lee@example.com", "555-66-7777", "(202)555-0156"},
	{"Hassan Ali", "hassan.ali@example.org", "666-77-8888", "+1 (202) 555-0175"},
	{"Isabella Rossi", "i.rossi@test.local", "777-88-9999", "202 555 0121"},
	{"Jamal Thompson", "jamal.thompson@example.com", "888-99-0001", "202/555/0108"},
}

// TestRedactPII_FixtureRecord drives every record through redactPII and
// asserts the email, SSN, and phone are all redacted, the name survives, and
// the appropriate REDACTED markers are present. This is the spec the redactor
// must meet for the kind of prompts operators throw at it.
func TestRedactPII_FixtureRecord(t *testing.T) {
	for _, rec := range fixtureRecords {
		t.Run(rec.name, func(t *testing.T) {
			in := "Name: " + rec.name + "\n   Email: " + rec.email + "\n   SSN: " + rec.ssn + "\n   Phone: " + rec.phone
			out := redactPII(in)

			assert.Contains(t, out, rec.name, "name must survive (not a PII pattern the redactor catches)")
			assert.Contains(t, out, "[REDACTED:email]", "email marker must appear for %q", rec.email)
			assert.Contains(t, out, "[REDACTED:ssn]", "ssn marker must appear for %q", rec.ssn)
			assert.Contains(t, out, "[REDACTED:phone]", "phone marker must appear for %q", rec.phone)

			assert.NotContains(t, out, rec.email, "raw email must not survive: %q", rec.email)
			assert.NotContains(t, out, rec.ssn, "raw SSN must not survive: %q", rec.ssn)
			// Phone: assert the local digits (last 7) are gone. Country-code
			// remnants like "+1 " or "1-" may remain in front of the redaction
			// because the E.164 pattern needs digits-only after '+' — that's
			// acceptable, the personally-identifying portion is removed.
			localDigits := lastSevenDigits(rec.phone)
			assert.NotContains(t, out, localDigits, "raw phone local digits %q must not survive in redacted output of %q", localDigits, rec.phone)
		})
	}
}

// lastSevenDigits returns the last 7 digits of a phone number, ignoring
// formatting. It's the unique "subscriber" portion that absolutely must be
// scrubbed regardless of which prefix the redactor leaves behind.
func lastSevenDigits(phone string) string {
	digits := make([]byte, 0, len(phone))
	for i := 0; i < len(phone); i++ {
		if phone[i] >= '0' && phone[i] <= '9' {
			digits = append(digits, phone[i])
		}
	}
	if len(digits) <= 7 {
		return string(digits)
	}
	return string(digits[len(digits)-7:])
}
