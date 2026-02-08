package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/auth"
)

func TestRewriteFunc_HostRewriting(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}

	t.Run("rewrites host to backend by default", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "https://public.example.com/path", "203.0.113.1:12345")

		rewrite(pr)

		assert.Equal(t, "backend.internal:8080", pr.Out.Host)
	})

	t.Run("preserves original host when passHostHeader is true", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "", true)
		pr := newProxyRequest(t, "https://public.example.com/path", "203.0.113.1:12345")

		rewrite(pr)

		assert.Equal(t, "public.example.com", pr.Out.Host,
			"Host header should be the original client host")
		assert.Equal(t, "backend.internal:8080", pr.Out.URL.Host,
			"URL host (used for TLS/SNI) must still point to the backend")
	})
}

func TestRewriteFunc_XForwardedForStripping(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false)

	t.Run("sets X-Forwarded-For from direct connection IP", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Forwarded-For"),
			"should be set to the connecting client IP")
	})

	t.Run("strips spoofed X-Forwarded-For from client", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
		pr.In.Header.Set("X-Forwarded-For", "10.0.0.1, 172.16.0.1")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Forwarded-For"),
			"spoofed XFF must be replaced, not appended to")
	})

	t.Run("strips spoofed X-Real-IP from client", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
		pr.In.Header.Set("X-Real-IP", "10.0.0.1")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Real-IP"),
			"spoofed X-Real-IP must be replaced")
	})
}

func TestRewriteFunc_ForwardedHostAndProto(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")

	t.Run("sets X-Forwarded-Host to original host", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "http://myapp.example.com:8443/path", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "myapp.example.com:8443", pr.Out.Header.Get("X-Forwarded-Host"))
	})

	t.Run("sets X-Forwarded-Port from explicit host port", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "http://example.com:8443/path", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "8443", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("defaults X-Forwarded-Port to 443 for https", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "https://example.com/", "1.2.3.4:5000")
		pr.In.TLS = &tls.ConnectionState{}

		rewrite(pr)

		assert.Equal(t, "443", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("defaults X-Forwarded-Port to 80 for http", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "80", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("auto detects https from TLS", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "https://example.com/", "1.2.3.4:5000")
		pr.In.TLS = &tls.ConnectionState{}

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("auto detects http without TLS", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "http", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("forced proto overrides TLS detection", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "https"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		// No TLS, but forced to https

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("forced http proto", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "http"}
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "https://example.com/", "1.2.3.4:5000")
		pr.In.TLS = &tls.ConnectionState{}

		rewrite(pr)

		assert.Equal(t, "http", pr.Out.Header.Get("X-Forwarded-Proto"))
	})
}

func TestRewriteFunc_SessionCookieStripping(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false)

	t.Run("strips nb_session cookie", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		pr.In.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "jwt-token-here"})

		rewrite(pr)

		cookies := pr.Out.Cookies()
		for _, c := range cookies {
			assert.NotEqual(t, auth.SessionCookieName, c.Name,
				"proxy session cookie must not be forwarded to backend")
		}
	})

	t.Run("preserves other cookies", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		pr.In.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "jwt-token"})
		pr.In.AddCookie(&http.Cookie{Name: "app_session", Value: "app-value"})
		pr.In.AddCookie(&http.Cookie{Name: "tracking", Value: "track-value"})

		rewrite(pr)

		cookies := pr.Out.Cookies()
		cookieNames := make([]string, 0, len(cookies))
		for _, c := range cookies {
			cookieNames = append(cookieNames, c.Name)
		}
		assert.Contains(t, cookieNames, "app_session", "non-proxy cookies should be preserved")
		assert.Contains(t, cookieNames, "tracking", "non-proxy cookies should be preserved")
		assert.NotContains(t, cookieNames, auth.SessionCookieName, "proxy cookie must be stripped")
	})

	t.Run("handles request with no cookies", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Empty(t, pr.Out.Header.Get("Cookie"))
	})
}

func TestRewriteFunc_SessionTokenQueryStripping(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false)

	t.Run("strips session_token query parameter", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/callback?session_token=secret123&other=keep", "1.2.3.4:5000")

		rewrite(pr)

		assert.Empty(t, pr.Out.URL.Query().Get("session_token"),
			"OIDC session token must be stripped from backend request")
		assert.Equal(t, "keep", pr.Out.URL.Query().Get("other"),
			"other query parameters must be preserved")
	})

	t.Run("preserves query when no session_token present", func(t *testing.T) {
		pr := newProxyRequest(t, "http://example.com/api?foo=bar&baz=qux", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "bar", pr.Out.URL.Query().Get("foo"))
		assert.Equal(t, "qux", pr.Out.URL.Query().Get("baz"))
	})
}

func TestRewriteFunc_URLRewriting(t *testing.T) {
	p := &ReverseProxy{forwardedProto: "auto"}

	t.Run("rewrites URL to target with path prefix", func(t *testing.T) {
		target, _ := url.Parse("http://backend.internal:8080/app")
		rewrite := p.rewriteFunc(target, "", false)
		pr := newProxyRequest(t, "http://example.com/somepath", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "http", pr.Out.URL.Scheme)
		assert.Equal(t, "backend.internal:8080", pr.Out.URL.Host)
		assert.Equal(t, "/app/somepath", pr.Out.URL.Path,
			"SetURL should join the target base path with the request path")
	})

	t.Run("strips matched path prefix to avoid duplication", func(t *testing.T) {
		target, _ := url.Parse("https://backend.example.org:443/app")
		rewrite := p.rewriteFunc(target, "/app", false)
		pr := newProxyRequest(t, "http://example.com/app", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.URL.Scheme)
		assert.Equal(t, "backend.example.org:443", pr.Out.URL.Host)
		assert.Equal(t, "/app/", pr.Out.URL.Path,
			"matched path prefix should be stripped before joining with target path")
	})

	t.Run("strips matched prefix and preserves subpath", func(t *testing.T) {
		target, _ := url.Parse("https://backend.example.org:443/app")
		rewrite := p.rewriteFunc(target, "/app", false)
		pr := newProxyRequest(t, "http://example.com/app/article/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/app/article/123", pr.Out.URL.Path,
			"subpath after matched prefix should be preserved")
	})
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{"IPv4 with port", "192.168.1.1:12345", "192.168.1.1"},
		{"IPv6 with port", "[::1]:12345", "::1"},
		{"IPv6 full with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"IPv4 without port fallback", "192.168.1.1", "192.168.1.1"},
		{"IPv6 without brackets fallback", "::1", "::1"},
		{"empty string fallback", "", ""},
		{"public IP", "203.0.113.50:9999", "203.0.113.50"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractClientIP(tt.remoteAddr))
		})
	}
}

func TestExtractForwardedPort(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		resolvedProto string
		expected      string
	}{
		{"explicit port in host", "example.com:8443", "https", "8443"},
		{"explicit port overrides proto default", "example.com:9090", "http", "9090"},
		{"no port defaults to 443 for https", "example.com", "https", "443"},
		{"no port defaults to 80 for http", "example.com", "http", "80"},
		{"IPv6 host with port", "[::1]:8080", "http", "8080"},
		{"IPv6 host without port", "::1", "https", "443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractForwardedPort(tt.host, tt.resolvedProto))
		})
	}
}

func TestRewriteFunc_TrustedProxy(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	t.Run("appends to X-Forwarded-For", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50, 10.0.0.1", pr.Out.Header.Get("X-Forwarded-For"))
	})

	t.Run("preserves upstream X-Real-IP", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50")
		pr.In.Header.Set("X-Real-IP", "203.0.113.50")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Real-IP"))
	})

	t.Run("resolves X-Real-IP from XFF when not set by upstream", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Real-IP"),
			"should resolve real client through trusted chain")
	})

	t.Run("preserves upstream X-Forwarded-Host", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://proxy.internal/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-Host", "original.example.com")

		rewrite(pr)

		assert.Equal(t, "original.example.com", pr.Out.Header.Get("X-Forwarded-Host"))
	})

	t.Run("preserves upstream X-Forwarded-Proto", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-Proto", "https")

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("preserves upstream X-Forwarded-Port", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-Port", "8443")

		rewrite(pr)

		assert.Equal(t, "8443", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("falls back to local proto when upstream does not set it", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "https", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"),
			"should use configured forwardedProto as fallback")
	})

	t.Run("sets X-Forwarded-Host from request when upstream does not set it", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")

		rewrite(pr)

		assert.Equal(t, "example.com", pr.Out.Header.Get("X-Forwarded-Host"))
	})

	t.Run("untrusted RemoteAddr strips headers even with trusted list", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
		pr.In.Header.Set("X-Forwarded-For", "10.0.0.1, 172.16.0.1")
		pr.In.Header.Set("X-Real-IP", "evil")
		pr.In.Header.Set("X-Forwarded-Host", "evil.example.com")
		pr.In.Header.Set("X-Forwarded-Proto", "https")
		pr.In.Header.Set("X-Forwarded-Port", "9999")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Forwarded-For"),
			"untrusted: XFF must be replaced")
		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Real-IP"),
			"untrusted: X-Real-IP must be replaced")
		assert.Equal(t, "example.com", pr.Out.Header.Get("X-Forwarded-Host"),
			"untrusted: host must be from direct connection")
		assert.Equal(t, "http", pr.Out.Header.Get("X-Forwarded-Proto"),
			"untrusted: proto must be locally resolved")
		assert.Equal(t, "80", pr.Out.Header.Get("X-Forwarded-Port"),
			"untrusted: port must be locally computed")
	})

	t.Run("empty trusted list behaves as untrusted", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: nil}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50")

		rewrite(pr)

		assert.Equal(t, "10.0.0.1", pr.Out.Header.Get("X-Forwarded-For"),
			"nil trusted list: should strip and use RemoteAddr")
	})

	t.Run("XFF starts fresh when trusted proxy has no upstream XFF", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")

		rewrite(pr)

		assert.Equal(t, "10.0.0.1", pr.Out.Header.Get("X-Forwarded-For"),
			"no upstream XFF: should set direct connection IP")
	})
}

// newProxyRequest creates an httputil.ProxyRequest suitable for testing
// the Rewrite function. It simulates what httputil.ReverseProxy does internally:
// Out is a shallow clone of In with headers copied.
func newProxyRequest(t *testing.T, rawURL, remoteAddr string) *httputil.ProxyRequest {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	in := httptest.NewRequest(http.MethodGet, rawURL, nil)
	in.RemoteAddr = remoteAddr
	in.Host = parsed.Host

	out := in.Clone(in.Context())
	out.Header = in.Header.Clone()

	return &httputil.ProxyRequest{In: in, Out: out}
}
