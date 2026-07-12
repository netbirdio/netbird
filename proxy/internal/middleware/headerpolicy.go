package middleware

import "strings"

var denyHeaders = []string{
	"Authorization",
	"Connection",
	"Cookie",
	"Set-Cookie",
	"Forwarded",
	"Keep-Alive",
	"Proxy-Authorization",
	"Proxy-Authenticate",
	"Proxy-Connection",
	"TE",
	"Upgrade",
	"Via",
	"X-Real-IP",
	"X-Request-ID",
	"Host",
	"Content-Length",
	"Transfer-Encoding",
	"Trailer",
}

var denyHeaderPrefixes = []string{
	"X-Authenticated-",
	"X-Forwarded-",
	"X-Remote-",
	"X-NetBird-",
}

// IsHeaderMutable reports whether a middleware is allowed to mutate
// the named header. The check is case-insensitive and honours both
// exact matches and the compiled-in prefix denylist.
func IsHeaderMutable(name string) bool {
	if name == "" {
		return false
	}
	if !isHeaderFieldName(name) {
		return false
	}
	for _, d := range denyHeaders {
		if strings.EqualFold(d, name) {
			return false
		}
	}
	for _, p := range denyHeaderPrefixes {
		if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
			return false
		}
	}
	return true
}

// isHeaderFieldName reports whether name is a valid RFC 7230 header
// field-name (a non-empty token of tchar octets). Rejects names with
// spaces, control characters, or separators that could enable header
// injection or smuggling when applied to the outbound request.
func isHeaderFieldName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// FilterHeaderMutations returns the subsets of HeadersAdd and
// HeadersRemove that are safe to apply, plus the list of blocked
// header names so the dispatcher can increment the blocked-header
// metric.
func FilterHeaderMutations(m *Mutations) (filteredAdd []KV, filteredRemove []string, blocked []string) {
	if m == nil {
		return nil, nil, nil
	}
	for _, kv := range m.HeadersAdd {
		if IsHeaderMutable(kv.Key) {
			filteredAdd = append(filteredAdd, kv)
			continue
		}
		blocked = append(blocked, kv.Key)
	}
	for _, name := range m.HeadersRemove {
		if IsHeaderMutable(name) {
			filteredRemove = append(filteredRemove, name)
			continue
		}
		blocked = append(blocked, name)
	}
	return filteredAdd, filteredRemove, blocked
}
