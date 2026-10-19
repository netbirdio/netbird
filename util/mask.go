package util

import (
	"net/url"
	"strings"
)

const masked = "xxxxx"

// MaskCredentials masks the password in a connection string: a key=value DSN, a
// "user:pass@host" DSN, or one or more comma-separated URLs.
func MaskCredentials(value string) string {
	if strings.Contains(value, "password=") {
		fields := strings.Fields(value)
		for i, field := range fields {
			if strings.HasPrefix(field, "password=") {
				fields[i] = "password=" + masked
			}
		}
		return strings.Join(fields, " ")
	}
	if strings.Count(value, "://") < 2 {
		return maskUserinfo(value)
	}
	urls := strings.Split(value, ",")
	for i, raw := range urls {
		urls[i] = maskUserinfo(strings.TrimSpace(raw))
	}
	return strings.Join(urls, ",")
}

// MaskSecret keeps the first 4 characters of secret.
func MaskSecret(secret string) string {
	if len(secret) <= 4 {
		return masked
	}
	return secret[:4] + "..."
}

func maskUserinfo(raw string) string {
	at := strings.Index(raw, "@")
	if at == -1 {
		return raw
	}
	if !strings.Contains(raw, "://") {
		if colon := strings.Index(raw[:at], ":"); colon != -1 {
			return raw[:colon+1] + masked + raw[at:]
		}
		return raw
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return masked
	case u.User == nil:
		return raw
	}
	if _, ok := u.User.Password(); ok {
		return u.Redacted()
	}
	// A lone username is used as the password.
	u.User = url.User(masked)
	return u.String()
}
