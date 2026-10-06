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

// TestRedactPIIPhoneInternational covers numbers outside North America the way
// people actually write them: with a country code and separators, in national
// format with a trunk prefix, or with a 00 international prefix. The subscriber
// digits must not survive, whatever prefix the redactor leaves behind.
func TestRedactPIIPhoneInternational(t *testing.T) {
	cases := []string{
		"+49 151 23456789",
		"+49-151-23456789",
		"+49 (0)151 23456789",
		"+49 30 12345678",
		"+44 20 7946 0958",
		"+33 1 23 45 67 89",
		"+1 202 555 0188",
		"0049 151 23456789",
		"0151 23456789",
		"030 12345678",
	}
	for _, phone := range cases {
		t.Run(phone, func(t *testing.T) {
			out := redactPII("call me at " + phone + " anytime")
			assert.Equal(t, "call me at [REDACTED:phone] anytime", out, "the whole number must be redacted for %q", phone)
		})
	}
}

// TestRedactPIIPhoneGerman covers German numbers as DIN 5008 writes them and
// in the older or informal styles still common in signatures and prompts: area
// codes of two to five digits, mobile and service prefixes, extensions, the
// "(0)" trunk-prefix notation and numbers without any separators.
func TestRedactPIIPhoneGerman(t *testing.T) {
	cases := []string{
		// DIN 5008
		"030 12345678",
		"030 1234567-89",
		"0151 23456789",
		"+49 30 12345678",
		"+49 30 1234567-89",
		"+49 151 23456789",
		// older and informal styles
		"(030) 12345678",
		"030/12345678",
		"030-12345678",
		"030.12345678",
		"0151/23456789",
		"0151-23456789",
		"+49 (0)30 12345678",
		"+49 (0) 30 12345678",
		"+49 (0)151 23456789",
		"0049 30 12345678",
		"+49-30-12345678",
		"(0)30 12345678",
		"(0) 30 12345678",
		"(0) 151 23456789",
		"0 30 12345678",
		"0 151 23456789",
		// no separators
		"03012345678",
		"015123456789",
		"+493012345678",
		// area codes of two to five digits
		"089 12345",
		"0221 1234567",
		"06221 123456",
		"033203 1234",
		// mobile prefixes and grouping
		"0171 1234567",
		"0160 1234567",
		"01512 3456789",
		"0151 2345 6789",
		"0176 123 456 78",
		// service numbers
		"0800 1234567",
		"0180 5 123456",
		"0900 1234567",
	}
	for _, phone := range cases {
		t.Run(phone, func(t *testing.T) {
			out := redactPII("Tel.: " + phone + " (Büro)")
			assert.Equal(t, "Tel.: [REDACTED:phone] (Büro)", out, "the whole number must be redacted for %q", phone)
		})
	}
}

// TestRedactPIIPhoneSpaceSeparatedDate documents an accepted over-redaction. A
// date written with spaces only ("05 10 2026") is redacted as a phone number,
// because treating "dd mm yy" with spaces as a date would leave French numbers
// such as "01 23 45 67 89" in the clear. Leaking a number is worse than hiding a
// rarely written date.
func TestRedactPIIPhoneSpaceSeparatedDate(t *testing.T) {
	assert.Equal(t, "am [REDACTED:phone]", redactPII("am 05 10 2026"),
		"space-separated date is redacted as a phone number by design")
	assert.Equal(t, "Tel. [REDACTED:phone]", redactPII("Tel. 01 23 45 67 89"),
		"French number in pairs must be redacted")
}

// TestRedactPIIPhoneKeepsSurroundingParentheses checks that a number wrapped in
// parentheses is redacted without unbalancing them.
func TestRedactPIIPhoneKeepsSurroundingParentheses(t *testing.T) {
	assert.Equal(t, "Rückruf ([REDACTED:phone]) bitte", redactPII("Rückruf (0151 23456789) bitte"),
		"national number in parentheses must keep both parentheses")
	assert.Equal(t, "Rückruf ([REDACTED:phone]) bitte", redactPII("Rückruf (+49 151 23456789) bitte"),
		"international number in parentheses must keep both parentheses")
}

// TestRedactPIIPhoneFalsePositives guards the other direction: digit runs that
// commonly appear in prompts but are not phone numbers must not be redacted as
// phones.
func TestRedactPIIPhoneFalsePositives(t *testing.T) {
	cases := []string{
		"born on 1985-03-14",
		"released 2026-10-06 at 10:45:30",
		"upgrade to version 1.27.1",
		"expiry 12/29, CVV 123",
		"listen on port 51820",
		"server 203.0.113.42 is down",
		"invoice #4711 for 1499.00 EUR",
		"meeting on 05.10.2026",
		"meeting on 05/10/26",
		"build 0.27.1-rc1",
		"see RFC 0791 section 3",
		"zip 01067 Dresden",
		"order 0012345",
		"am 05.10.2026 08:30",
		"05.10.2026 14:00",
		"05/10/2026 14:00 Uhr",
		"2026-01-05 08:30:00",
		"2026-01-05T08:30:00Z",
		"2026-01-05T08:30:00.123+02:00",
		"2026/01/05 08:30",
		"from 2026-01-05 to 2026-02-07",
		"vom 05.10.2026\u201330.11.2026",
		"vom 05.10.2026-30.11.2026",
		"am 05.10.2026-09:30 Uhr",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			out := redactPII(in)
			assert.NotContains(t, out, "[REDACTED:phone]", "non-phone input must not be redacted as a phone: %q -> %q", in, out)
		})
	}
}

// TestRedactPIIPhoneUnicodeSeparators covers numbers written with the Unicode
// spaces and dashes that word processors, chat clients and LLM completions put
// between digit groups instead of ASCII spaces and hyphens.
func TestRedactPIIPhoneUnicodeSeparators(t *testing.T) {
	cases := map[string]string{
		"narrow no-break space": "+49 151 23456789",
		"no-break space":        "+49 151 23456789",
		"thin space":            "0151 23456789",
		"figure space":          "030 12345678",
		"non-breaking hyphen":   "030‑1234567‑89",
		"en dash":               "0151–23456789",
		"north american nbsp":   "(415) 555 1234",
	}
	for name, phone := range cases {
		t.Run(name, func(t *testing.T) {
			out := redactPII("Tel.: " + phone + " (Büro)")
			assert.Equal(t, "Tel.: [REDACTED:phone] (Büro)", out, "the whole number must be redacted for %q", phone)
		})
	}
}

// TestRedactPIIPhoneAfterDate checks that a date directly followed by a number
// keeps the date and still redacts the number, instead of exempting both.
func TestRedactPIIPhoneAfterDate(t *testing.T) {
	cases := map[string]string{
		"am 05.10.2026 0151 23456789":   "am 05.10.2026 [REDACTED:phone]",
		"am 05/10/2026 030 12345678":    "am 05/10/2026 [REDACTED:phone]",
		"am 05.10.2026 +49 30 12345678": "am 05.10.2026 [REDACTED:phone]",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, redactPII(in), "the date must survive and the number must be redacted")
		})
	}
}

// TestRedactPIIPhoneStopsAtLineBreak checks that a candidate does not run
// across a line break into the next line.
func TestRedactPIIPhoneStopsAtLineBreak(t *testing.T) {
	in := "Tel. 030 12345678\n2026 report"
	assert.Equal(t, "Tel. [REDACTED:phone]\n2026 report", redactPII(in),
		"redaction must stop at the end of the line")
}
