package util

import (
	"net/url"
	"regexp"
	"strings"
)

const masked = "xxxxx"

// Matches a key=value DSN password, quoted or not: password='a b', sslpassword = x.
var dsnPassword = regexp.MustCompile(`(\w*password)\s*=\s*('(?:\\.|[^'\\])*'|\S*)`)

// MaskCredentials masks the password in a connection string: a key=value DSN, a
// "user:pass@host" DSN, or one or more comma-separated URLs.
func MaskCredentials(value string) string {
	if !strings.Contains(value, "://") && dsnPassword.MatchString(value) {
		return dsnPassword.ReplaceAllString(value, "${1}="+masked)
	}
	var urls []string
	for _, part := range strings.Split(value, ",") {
		if n := len(urls); n > 0 && !strings.Contains(part, "://") {
			urls[n-1] += "," + part // a comma inside the previous URL
			continue
		}
		urls = append(urls, part)
	}
	for i, raw := range urls {
		urls[i] = maskUserinfo(strings.TrimSpace(raw))
	}
	return strings.Join(urls, ",")
}

// MaskSecret keeps the first 4 characters of secret.
func MaskSecret(secret string) string {
	r := []rune(secret)
	if len(r) <= 4 {
		return masked
	}
	return string(r[:4]) + "..."
}

func maskUserinfo(raw string) string {
	if !strings.Contains(raw, "://") {
		at := strings.LastIndex(raw, "@")
		if at == -1 {
			return raw
		}
		if colon := strings.Index(raw[:at], ":"); colon != -1 {
			return raw[:colon+1] + masked + raw[at:]
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(raw, "@") || strings.Contains(raw, "password=") {
			return masked
		}
		return raw
	}
	q := u.Query()
	if u.User == nil && !q.Has("password") {
		return raw
	}
	if q.Has("password") {
		q.Set("password", masked)
		u.RawQuery = q.Encode()
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), masked)
		} else {
			// A lone username is used as the password.
			u.User = url.User(masked)
		}
	}
	return u.String()
}
