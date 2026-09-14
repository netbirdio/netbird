package middleware

import (
	"regexp"
	"strings"
)

// Redaction scope: Scan handles the narrow, high-signal set of
// secrets we are comfortable masking with a regex. The intent is
// "make accidental leaks impossible to miss at a glance", not "be a
// DLP product". Contributors adding more patterns should weigh false
// positives carefully — a metadata value that over-redacts benign
// strings is strictly worse than one that misses a rare format.
var (
	jwtRegex       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)
	pemRegex       = regexp.MustCompile(`-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----`)
	awsKeyRegex    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	bearerRegex    = regexp.MustCompile(`(?i)\b(?:bearer|token|api[_-]?key|authorization)[\s:=]+([A-Za-z0-9_\-\.]{40,})`)
	ccCandidateRgx = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
)

// Scan redacts high-signal secret patterns from value. Matches are
// replaced with `[REDACTED:<kind>]`. Non-matching input is returned
// unchanged.
func Scan(value string) string {
	if value == "" {
		return value
	}
	result := value
	result = pemRegex.ReplaceAllString(result, "[REDACTED:pem]")
	result = jwtRegex.ReplaceAllString(result, "[REDACTED:jwt]")
	result = awsKeyRegex.ReplaceAllString(result, "[REDACTED:aws_key]")
	result = bearerRegex.ReplaceAllStringFunc(result, func(match string) string {
		sub := bearerRegex.FindStringSubmatch(match)
		if len(sub) < 2 {
			return "[REDACTED:bearer]"
		}
		return strings.Replace(match, sub[1], "[REDACTED:bearer]", 1)
	})
	result = ccCandidateRgx.ReplaceAllStringFunc(result, func(match string) string {
		digits := stripNonDigits(match)
		if len(digits) < 13 || len(digits) > 19 {
			return match
		}
		if !luhn(digits) {
			return match
		}
		return "[REDACTED:cc]"
	})
	return result
}

func stripNonDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
