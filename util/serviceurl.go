package util

import (
	"net/url"
	"strconv"
	"strings"
)

// SameServiceURL reports whether two service URLs address the same endpoint.
// One endpoint can be written several ways, and every spelling below reaches
// the same server, so none of them is a divergence from another:
//
//	an implicit default port    https://mgmt.example.com   :443
//	a zero-padded port          https://mgmt.example.com:0443
//	a different host case       https://MGMT.example.com
//	a trailing slash            https://mgmt.example.com/
//
// A path is otherwise part of the identity: https://mgmt.example.com and
// https://mgmt.example.com/other are two endpoints.
//
// It lives here rather than next to any one caller because several of them
// compare the same kind of URL — an MDM-enforced management URL against a
// requested one, a stored profile URL against a command-line one — and every
// copy of these rules that drifts turns an equivalent URL into a refused
// request.
func SameServiceURL(a, b *url.URL) bool {
	if a == nil || b == nil {
		return a == b
	}

	return strings.EqualFold(a.Hostname(), b.Hostname()) &&
		strings.EqualFold(a.Scheme, b.Scheme) &&
		ServiceURLPort(a) == ServiceURLPort(b) &&
		strings.TrimSuffix(a.Path, "/") == strings.TrimSuffix(b.Path, "/")
}

// SameServiceURLStrings is SameServiceURL for unparsed input. Input that does
// not parse falls back to string equality, which is the strictest thing left
// to do with it.
func SameServiceURLStrings(a, b string) bool {
	ua, errA := url.ParseRequestURI(a)
	ub, errB := url.ParseRequestURI(b)
	if errA != nil || errB != nil {
		return a == b
	}

	return SameServiceURL(ua, ub)
}

// ServiceURLPort is the port a URL addresses: the one it carries, normalized
// numerically so ":0443" and ":443" are one port, or the scheme's default.
func ServiceURLPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			return "443"
		case "http":
			return "80"
		default:
			return ""
		}
	}

	if n, err := strconv.Atoi(port); err == nil {
		return strconv.Itoa(n)
	}
	return port
}
