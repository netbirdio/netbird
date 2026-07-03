package llm_guardrail

import (
	"regexp"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// PII redactor scope: redact prompt content BEFORE it lands in the metadata
// bag. The bearer-with-keyword pass runs first so the keyword is preserved.
// We then chain the package-level middleware.Scan to pick up PEM, JWT, AWS
// access keys, generic bearer tokens (40+ chars), and Luhn-validated credit
// cards — keeping prompt redaction in sync with metadata-value scanning. Email,
// SSN (dashed form), phone (E.164 + NA), and IPv4 are prompt-shaped patterns
// the metadata scanner intentionally leaves alone.
var (
	emailRegex = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	ssnRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	phoneE164  = regexp.MustCompile(`\+\d{8,15}\b`)
	// phoneNARgx accepts the 3-3-4 North-American shape with any of the common
	// separators (space, dot, dash, slash) or none at all between the area code
	// and the body. The optional `\(?...\)?` wraps the area code; the separator
	// classes use `*` (not `?`) so multi-char separators ("(202) " followed by
	// space-and-something) and zero-separator runs ("2025550134") both match.
	// False-positive tradeoff: 10 consecutive digits in a prompt will be
	// treated as a phone number. For PII redaction that is the correct way to
	// err — under-redaction leaks; over-redaction is annoying.
	phoneNARgx  = regexp.MustCompile(`\(?\b\d{3}\)?[\s.\-/]*\d{3}[\s.\-/]*\d{4}\b`)
	bearerRegex = regexp.MustCompile(`(?i)\b(bearer|token|api[_-]?key|authorization)([\s:=]+)(\S{20,})`)
	ipv4Regex   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
)

// redactPII is the package-private alias kept for internal callers; new code
// outside the guardrail middleware should call RedactPII.
func redactPII(value string) string { return RedactPII(value) }

// RedactPII replaces high-signal PII patterns in value with
// `[REDACTED:<kind>]`. Non-matching input is returned unchanged. Exported so
// the request / response parsers can reuse the same coverage on raw prompts
// and completions when the account's redact_pii toggle is on.
func RedactPII(value string) string {
	if value == "" {
		return value
	}
	result := value
	// Keyword-preserving bearer first so the "bearer "/"token=" prefix survives
	// before the generic scanner gets at the same content.
	result = bearerRegex.ReplaceAllStringFunc(result, redactBearer)
	// Structured secrets shared with metadata-value scanning: PEM, JWT, AWS
	// keys, generic bearer (40+), and Luhn-validated credit cards.
	result = middleware.Scan(result)
	// Prompt-shaped PII the metadata scanner doesn't cover.
	result = emailRegex.ReplaceAllString(result, "[REDACTED:email]")
	result = ssnRegex.ReplaceAllString(result, "[REDACTED:ssn]")
	result = phoneE164.ReplaceAllString(result, "[REDACTED:phone]")
	result = phoneNARgx.ReplaceAllString(result, "[REDACTED:phone]")
	result = ipv4Regex.ReplaceAllString(result, "[REDACTED:ip]")
	return result
}

// redactBearer keeps the leading keyword and its separator, replacing
// only the secret payload so the surrounding context is preserved.
func redactBearer(match string) string {
	sub := bearerRegex.FindStringSubmatch(match)
	if len(sub) < 4 {
		return "[REDACTED:bearer]"
	}
	var b strings.Builder
	b.Grow(len(sub[1]) + len(sub[2]) + len("[REDACTED:bearer]"))
	b.WriteString(sub[1])
	b.WriteString(sub[2])
	b.WriteString("[REDACTED:bearer]")
	return b.String()
}
