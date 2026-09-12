package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/trustedproxy"
)

func TestRewriteFunc_HostRewriting(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}

	t.Run("rewrites host to backend by default", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "https://public.example.com/path", "203.0.113.1:12345")

		rewrite(pr)

		assert.Equal(t, "backend.internal:8080", pr.Out.Host)
	})

	t.Run("preserves original host when passHostHeader is true", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "", true, PathRewriteDefault, nil, nil)
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
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

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
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://myapp.example.com:8443/path", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "myapp.example.com:8443", pr.Out.Header.Get("X-Forwarded-Host"))
	})

	t.Run("sets X-Forwarded-Port from explicit host port", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com:8443/path", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "8443", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("defaults X-Forwarded-Port to 443 for https", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "https://example.com/", "1.2.3.4:5000")
		pr.In.TLS = &tls.ConnectionState{}

		rewrite(pr)

		assert.Equal(t, "443", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("defaults X-Forwarded-Port to 80 for http", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "80", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("auto detects https from TLS", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "https://example.com/", "1.2.3.4:5000")
		pr.In.TLS = &tls.ConnectionState{}

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("auto detects http without TLS", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "http", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("forced proto overrides TLS detection", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "https"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		// No TLS, but forced to https

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("forced http proto", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "http"}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "https://example.com/", "1.2.3.4:5000")
		pr.In.TLS = &tls.ConnectionState{}

		rewrite(pr)

		assert.Equal(t, "http", pr.Out.Header.Get("X-Forwarded-Proto"))
	})
}

func TestRewriteFunc_SessionCookieStripping(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

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

	t.Run("preserves JSON cookie values with RFC-invalid octets", func(t *testing.T) {
		// Logto / node-oidc-provider set cookies like:
		//   _interaction={"admin-console":"uid","_legacy":"uid"}
		// Go's http.Cookie parser drops these; the proxy must forward the raw header.
		pr := newProxyRequest(t, "http://example.com/sign-in", "1.2.3.4:5000")
		pr.In.Header.Set("Cookie",
			`_logto={"appId":"admin-console"}; _interaction={"admin-console":"abc","_legacy":"abc"}; _interaction.sig=xyz; nb_session=secret`)

		rewrite(pr)

		out := pr.Out.Header.Get("Cookie")
		assert.Contains(t, out, `_interaction={"admin-console":"abc","_legacy":"abc"}`)
		assert.Contains(t, out, `_logto={"appId":"admin-console"}`)
		assert.Contains(t, out, `_interaction.sig=xyz`)
		assert.NotContains(t, out, "nb_session=")
	})

	t.Run("preserves cookies across multiple Cookie headers", func(t *testing.T) {
		// HTTP/2 clients may send one cookie per Cookie header.
		pr := newProxyRequest(t, "http://example.com/sign-in", "1.2.3.4:5000")
		pr.In.Header["Cookie"] = []string{
			`_interaction={"admin-console":"abc","_legacy":"abc"}`,
			`_interaction.sig=xyz; nb_session=secret`,
		}

		rewrite(pr)

		out := pr.Out.Header.Get("Cookie")
		assert.Contains(t, out, `_interaction={"admin-console":"abc","_legacy":"abc"}`)
		assert.Contains(t, out, `_interaction.sig=xyz`)
		assert.NotContains(t, out, "nb_session=")
	})
}

func TestRewriteFunc_SessionTokenQueryStripping(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

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
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/somepath", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "http", pr.Out.URL.Scheme)
		assert.Equal(t, "backend.internal:8080", pr.Out.URL.Host)
		assert.Equal(t, "/app/somepath", pr.Out.URL.Path,
			"SetURL should join the target base path with the request path")
	})

	t.Run("strips matched path prefix to avoid duplication", func(t *testing.T) {
		target, _ := url.Parse("https://backend.example.org:443/app")
		rewrite := p.rewriteFunc(target, "/app", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/app", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.URL.Scheme)
		assert.Equal(t, "backend.example.org:443", pr.Out.URL.Host)
		assert.Equal(t, "/app/", pr.Out.URL.Path,
			"matched path prefix should be stripped before joining with target path")
	})

	t.Run("strips matched prefix and preserves subpath", func(t *testing.T) {
		target, _ := url.Parse("https://backend.example.org:443/app")
		rewrite := p.rewriteFunc(target, "/app", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/app/article/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/app/article/123", pr.Out.URL.Path,
			"subpath after matched prefix should be preserved")
	})
}

func TestExtractHostIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   netip.Addr
	}{
		{"IPv4 with port", "192.168.1.1:12345", netip.MustParseAddr("192.168.1.1")},
		{"IPv6 with port", "[::1]:12345", netip.MustParseAddr("::1")},
		{"IPv6 full with port", "[2001:db8::1]:443", netip.MustParseAddr("2001:db8::1")},
		{"IPv4 without port fallback", "192.168.1.1", netip.MustParseAddr("192.168.1.1")},
		{"IPv6 without brackets fallback", "::1", netip.MustParseAddr("::1")},
		{"empty string fallback", "", netip.Addr{}},
		{"public IP", "203.0.113.50:9999", netip.MustParseAddr("203.0.113.50")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, trustedproxy.ExtractHostIP(tt.remoteAddr))
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
	trusted := trustedproxy.FromPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	t.Run("appends to X-Forwarded-For", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50, 10.0.0.1", pr.Out.Header.Get("X-Forwarded-For"))
	})

	t.Run("preserves upstream X-Real-IP", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50")
		pr.In.Header.Set("X-Real-IP", "203.0.113.50")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Real-IP"))
	})

	t.Run("resolves X-Real-IP from XFF when not set by upstream", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")

		rewrite(pr)

		assert.Equal(t, "203.0.113.50", pr.Out.Header.Get("X-Real-IP"),
			"should resolve real client through trusted chain")
	})

	t.Run("preserves upstream X-Forwarded-Host", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://proxy.internal/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-Host", "original.example.com")

		rewrite(pr)

		assert.Equal(t, "original.example.com", pr.Out.Header.Get("X-Forwarded-Host"))
	})

	t.Run("preserves upstream X-Forwarded-Proto", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-Proto", "https")

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
	})

	t.Run("preserves upstream X-Forwarded-Port", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-Port", "8443")

		rewrite(pr)

		assert.Equal(t, "8443", pr.Out.Header.Get("X-Forwarded-Port"))
	})

	t.Run("falls back to local proto when upstream does not set it", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "https", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")

		rewrite(pr)

		assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"),
			"should use configured forwardedProto as fallback")
	})

	t.Run("sets X-Forwarded-Host from request when upstream does not set it", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")

		rewrite(pr)

		assert.Equal(t, "example.com", pr.Out.Header.Get("X-Forwarded-Host"))
	})

	t.Run("untrusted RemoteAddr strips headers even with trusted list", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

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
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")
		pr.In.Header.Set("X-Forwarded-For", "203.0.113.50")

		rewrite(pr)

		assert.Equal(t, "10.0.0.1", pr.Out.Header.Get("X-Forwarded-For"),
			"nil trusted list: should strip and use RemoteAddr")
	})

	t.Run("XFF starts fresh when trusted proxy has no upstream XFF", func(t *testing.T) {
		p := &ReverseProxy{forwardedProto: "auto", trustedProxies: trusted}
		rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

		pr := newProxyRequest(t, "http://example.com/", "10.0.0.1:5000")

		rewrite(pr)

		assert.Equal(t, "10.0.0.1", pr.Out.Header.Get("X-Forwarded-For"),
			"no upstream XFF: should set direct connection IP")
	})
}

// TestRewriteFunc_PathForwarding verifies what path the backend actually
// receives given different configurations. This simulates the full pipeline:
// management builds a target URL (with matching prefix baked into the path),
// then the proxy strips the prefix and SetURL re-joins with the target path.
func TestRewriteFunc_PathForwarding(t *testing.T) {
	p := &ReverseProxy{forwardedProto: "auto"}

	// Simulate what ToProtoMapping does: target URL includes the matching
	// prefix as its path component, so the proxy strips-then-re-adds.
	t.Run("path prefix baked into target URL is a no-op", func(t *testing.T) {
		// Management builds: path="/heise", target="https://heise.de:443/heise"
		target, _ := url.Parse("https://heise.de:443/heise")
		rewrite := p.rewriteFunc(target, "/heise", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://external.test/heise", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/heise/", pr.Out.URL.Path,
			"backend sees /heise/ because prefix is stripped then re-added by SetURL")
	})

	t.Run("subpath under prefix also preserved", func(t *testing.T) {
		target, _ := url.Parse("https://heise.de:443/heise")
		rewrite := p.rewriteFunc(target, "/heise", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://external.test/heise/article/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/heise/article/123", pr.Out.URL.Path,
			"subpath is preserved on top of the re-added prefix")
	})

	// What the behavior WOULD be if target URL had no path (true stripping)
	t.Run("target without path prefix gives true stripping", func(t *testing.T) {
		target, _ := url.Parse("https://heise.de:443")
		rewrite := p.rewriteFunc(target, "/heise", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://external.test/heise", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/", pr.Out.URL.Path,
			"without path in target URL, backend sees / (true prefix stripping)")
	})

	t.Run("target without path prefix strips and preserves subpath", func(t *testing.T) {
		target, _ := url.Parse("https://heise.de:443")
		rewrite := p.rewriteFunc(target, "/heise", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://external.test/heise/article/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/article/123", pr.Out.URL.Path,
			"without path in target URL, prefix is truly stripped")
	})

	// Root path "/" — no stripping expected
	t.Run("root path forwards full request path unchanged", func(t *testing.T) {
		target, _ := url.Parse("https://backend.example.com:443/")
		rewrite := p.rewriteFunc(target, "/", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://external.test/heise", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/heise", pr.Out.URL.Path,
			"root path match must not strip anything")
	})
}

func TestRewriteFunc_PreservePath(t *testing.T) {
	p := &ReverseProxy{forwardedProto: "auto"}
	target, _ := url.Parse("http://backend.internal:8080")

	t.Run("preserve keeps full request path", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "/api", false, PathRewritePreserve, nil, nil)
		pr := newProxyRequest(t, "http://example.com/api/users/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/api/users/123", pr.Out.URL.Path,
			"preserve should keep the full original request path")
	})

	t.Run("preserve with root matchedPath", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "/", false, PathRewritePreserve, nil, nil)
		pr := newProxyRequest(t, "http://example.com/anything", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/anything", pr.Out.URL.Path)
	})
}

func TestRewriteFunc_CustomHeaders(t *testing.T) {
	p := &ReverseProxy{forwardedProto: "auto"}
	target, _ := url.Parse("http://backend.internal:8080")

	t.Run("injects custom headers", func(t *testing.T) {
		headers := map[string]string{
			"X-Custom-Auth": "token-abc",
			"X-Env":         "production",
		}
		rewrite := p.rewriteFunc(target, "/", false, PathRewriteDefault, headers, nil)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "token-abc", pr.Out.Header.Get("X-Custom-Auth"))
		assert.Equal(t, "production", pr.Out.Header.Get("X-Env"))
	})

	t.Run("nil customHeaders is fine", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "/", false, PathRewriteDefault, nil, nil)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "backend.internal:8080", pr.Out.Host)
	})

	t.Run("custom headers override existing request headers", func(t *testing.T) {
		headers := map[string]string{"X-Override": "new-value"}
		rewrite := p.rewriteFunc(target, "/", false, PathRewriteDefault, headers, nil)
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		pr.In.Header.Set("X-Override", "old-value")

		rewrite(pr)

		assert.Equal(t, "new-value", pr.Out.Header.Get("X-Override"))
	})
}

func TestRewriteFunc_StripsAuthorizationHeader(t *testing.T) {
	p := &ReverseProxy{forwardedProto: "auto"}
	target, _ := url.Parse("http://backend.internal:8080")

	t.Run("strips incoming Authorization when no custom Authorization set", func(t *testing.T) {
		rewrite := p.rewriteFunc(target, "/", false, PathRewriteDefault, nil, []string{"Authorization"})
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		pr.In.Header.Set("Authorization", "Bearer proxy-token")

		rewrite(pr)

		assert.Empty(t, pr.Out.Header.Get("Authorization"), "Authorization should be stripped")
	})

	t.Run("custom Authorization replaces incoming", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Basic YmFja2VuZDpzZWNyZXQ="}
		rewrite := p.rewriteFunc(target, "/", false, PathRewriteDefault, headers, []string{"Authorization"})
		pr := newProxyRequest(t, "http://example.com/", "1.2.3.4:5000")
		pr.In.Header.Set("Authorization", "Bearer proxy-token")

		rewrite(pr)

		assert.Equal(t, "Basic YmFja2VuZDpzZWNyZXQ=", pr.Out.Header.Get("Authorization"),
			"backend Authorization from custom headers should be set")
	})
}

func TestRewriteFunc_PreservePathWithCustomHeaders(t *testing.T) {
	p := &ReverseProxy{forwardedProto: "auto"}
	target, _ := url.Parse("http://backend.internal:8080")

	rewrite := p.rewriteFunc(target, "/api", false, PathRewritePreserve, map[string]string{"X-Via": "proxy"}, nil)
	pr := newProxyRequest(t, "http://example.com/api/deep/path", "1.2.3.4:5000")

	rewrite(pr)

	assert.Equal(t, "/api/deep/path", pr.Out.URL.Path, "preserve should keep the full original path")
	assert.Equal(t, "proxy", pr.Out.Header.Get("X-Via"), "custom header should be set")
}

func TestRewriteLocationFunc(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	newProxy := func(proto string) *ReverseProxy { return &ReverseProxy{forwardedProto: proto} }
	newReq := func(rawURL string) *http.Request {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, rawURL, nil)
		parsed, _ := url.Parse(rawURL)
		r.Host = parsed.Host
		return r
	}
	run := func(p *ReverseProxy, matchedPath string, inReq *http.Request, location string) (*http.Response, error) {
		t.Helper()
		modifyResp := p.rewriteLocationFunc(target, matchedPath, inReq) //nolint:bodyclose
		resp := &http.Response{Header: http.Header{}}
		if location != "" {
			resp.Header.Set("Location", location)
		}
		err := modifyResp(resp)
		return resp, err
	}

	t.Run("rewrites Location pointing to backend", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/page"), //nolint:bodyclose
			"http://backend.internal:8080/login")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/login", resp.Header.Get("Location"))
	})

	t.Run("does not rewrite Location pointing to other host", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"https://other.example.com/path")

		require.NoError(t, err)
		assert.Equal(t, "https://other.example.com/path", resp.Header.Get("Location"))
	})

	t.Run("does not rewrite relative Location", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"/dashboard")

		require.NoError(t, err)
		assert.Equal(t, "/dashboard", resp.Header.Get("Location"))
	})

	t.Run("re-adds stripped path prefix", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/api", newReq("https://public.example.com/api/users"), //nolint:bodyclose
			"http://backend.internal:8080/users")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/api/users", resp.Header.Get("Location"))
	})

	t.Run("uses resolved proto for scheme", func(t *testing.T) {
		resp, err := run(newProxy("auto"), "", newReq("http://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:8080/path")

		require.NoError(t, err)
		assert.Equal(t, "http://public.example.com/path", resp.Header.Get("Location"))
	})

	t.Run("no-op when Location header is empty", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), "") //nolint:bodyclose

		require.NoError(t, err)
		assert.Empty(t, resp.Header.Get("Location"))
	})

	t.Run("does not prepend root path prefix", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/", newReq("https://public.example.com/login"), //nolint:bodyclose
			"http://backend.internal:8080/login")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/login", resp.Header.Get("Location"))
	})

	// --- Edge cases: query parameters and fragments ---

	t.Run("preserves query parameters", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:8080/login?redirect=%2Fdashboard&lang=en")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/login?redirect=%2Fdashboard&lang=en", resp.Header.Get("Location"))
	})

	t.Run("preserves fragment", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:8080/docs#section-2")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/docs#section-2", resp.Header.Get("Location"))
	})

	t.Run("preserves query parameters and fragment together", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:8080/search?q=test&page=1#results")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/search?q=test&page=1#results", resp.Header.Get("Location"))
	})

	t.Run("preserves query parameters with path prefix re-added", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/api", newReq("https://public.example.com/api/search"), //nolint:bodyclose
			"http://backend.internal:8080/search?q=hello")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/api/search?q=hello", resp.Header.Get("Location"))
	})

	// --- Edge cases: slash handling ---

	t.Run("no double slash when matchedPath has trailing slash", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/api/", newReq("https://public.example.com/api/users"), //nolint:bodyclose
			"http://backend.internal:8080/users")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/api/users", resp.Header.Get("Location"))
	})

	t.Run("backend redirect to root with path prefix", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/app", newReq("https://public.example.com/app/"), //nolint:bodyclose
			"http://backend.internal:8080/")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/app/", resp.Header.Get("Location"))
	})

	t.Run("backend redirect to root with trailing-slash path prefix", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/app/", newReq("https://public.example.com/app/"), //nolint:bodyclose
			"http://backend.internal:8080/")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/app/", resp.Header.Get("Location"))
	})

	t.Run("preserves trailing slash on redirect path", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:8080/path/")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/path/", resp.Header.Get("Location"))
	})

	t.Run("backend redirect to bare root", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/page"), //nolint:bodyclose
			"http://backend.internal:8080/")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/", resp.Header.Get("Location"))
	})

	// --- Edge cases: host/port matching ---

	t.Run("does not rewrite when backend host matches but port differs", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:9090/other")

		require.NoError(t, err)
		assert.Equal(t, "http://backend.internal:9090/other", resp.Header.Get("Location"),
			"Different port means different host authority, must not rewrite")
	})

	t.Run("rewrites when redirect omits default port matching target", func(t *testing.T) {
		// Target is backend.internal:8080, redirect is to backend.internal (no port).
		// These are different authorities, so should NOT rewrite.
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal/path")

		require.NoError(t, err)
		assert.Equal(t, "http://backend.internal/path", resp.Header.Get("Location"),
			"backend.internal != backend.internal:8080, must not rewrite")
	})

	t.Run("rewrites when target has :443 but redirect omits it for https", func(t *testing.T) {
		// Target: heise.de:443, redirect: https://heise.de/path (no :443 because it's default)
		// Per RFC 3986, these are the same authority.
		target443, _ := url.Parse("https://heise.de:443")
		p := newProxy("https")
		modifyResp := p.rewriteLocationFunc(target443, "", newReq("https://public.example.com/")) //nolint:bodyclose
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", "https://heise.de/path")

		err := modifyResp(resp)

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/path", resp.Header.Get("Location"),
			"heise.de:443 and heise.de are the same for https")
	})

	t.Run("rewrites when target has :80 but redirect omits it for http", func(t *testing.T) {
		target80, _ := url.Parse("http://backend.local:80")
		p := newProxy("http")
		modifyResp := p.rewriteLocationFunc(target80, "", newReq("http://public.example.com/")) //nolint:bodyclose
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", "http://backend.local/path")

		err := modifyResp(resp)

		require.NoError(t, err)
		assert.Equal(t, "http://public.example.com/path", resp.Header.Get("Location"),
			"backend.local:80 and backend.local are the same for http")
	})

	t.Run("rewrites when redirect has :443 but target omits it", func(t *testing.T) {
		targetNoPort, _ := url.Parse("https://heise.de")
		p := newProxy("https")
		modifyResp := p.rewriteLocationFunc(targetNoPort, "", newReq("https://public.example.com/")) //nolint:bodyclose
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", "https://heise.de:443/path")

		err := modifyResp(resp)

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/path", resp.Header.Get("Location"),
			"heise.de and heise.de:443 are the same for https")
	})

	t.Run("does not conflate non-default ports", func(t *testing.T) {
		target8443, _ := url.Parse("https://backend.internal:8443")
		p := newProxy("https")
		modifyResp := p.rewriteLocationFunc(target8443, "", newReq("https://public.example.com/")) //nolint:bodyclose
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", "https://backend.internal/path")

		err := modifyResp(resp)

		require.NoError(t, err)
		assert.Equal(t, "https://backend.internal/path", resp.Header.Get("Location"),
			"backend.internal:8443 != backend.internal (port 443), must not rewrite")
	})

	// --- Edge cases: encoded paths ---

	t.Run("preserves percent-encoded path segments", func(t *testing.T) {
		resp, err := run(newProxy("https"), "", newReq("https://public.example.com/"), //nolint:bodyclose
			"http://backend.internal:8080/path%20with%20spaces/file%2Fname")

		require.NoError(t, err)
		loc := resp.Header.Get("Location")
		assert.Contains(t, loc, "public.example.com")
		parsed, err := url.Parse(loc)
		require.NoError(t, err)
		assert.Equal(t, "/path with spaces/file/name", parsed.Path)
	})

	t.Run("preserves encoded query parameters with path prefix", func(t *testing.T) {
		resp, err := run(newProxy("https"), "/v1", newReq("https://public.example.com/v1/"), //nolint:bodyclose
			"http://backend.internal:8080/redirect?url=http%3A%2F%2Fexample.com")

		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com/v1/redirect?url=http%3A%2F%2Fexample.com", resp.Header.Get("Location"))
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

func TestClassifyProxyError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantTitle  string
		wantCode   int
		wantStatus web.ErrorStatus
	}{
		{
			name:       "context deadline exceeded",
			err:        context.DeadlineExceeded,
			wantTitle:  "Request Timeout",
			wantCode:   http.StatusGatewayTimeout,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name:       "wrapped deadline exceeded",
			err:        fmt.Errorf("dial: %w", context.DeadlineExceeded),
			wantTitle:  "Request Timeout",
			wantCode:   http.StatusGatewayTimeout,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name:       "context canceled",
			err:        context.Canceled,
			wantTitle:  "Request Canceled",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name:       "no account ID",
			err:        roundtrip.ErrNoAccountID,
			wantTitle:  "Configuration Error",
			wantCode:   http.StatusInternalServerError,
			wantStatus: web.ErrorStatus{Proxy: false, Destination: false},
		},
		{
			name:       "no peer connection",
			err:        fmt.Errorf("%w for account: abc", roundtrip.ErrNoPeerConnection),
			wantTitle:  "Proxy Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: false, Destination: false},
		},
		{
			name:       "client not started",
			err:        fmt.Errorf("%w: %w", roundtrip.ErrClientStartFailed, errors.New("engine init failed")),
			wantTitle:  "Proxy Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: false, Destination: false},
		},
		{
			name: "syscall ECONNREFUSED via os.SyscallError",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
			},
			wantTitle:  "Service Unavailable",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name: "gvisor connection was refused",
			err: &net.OpError{
				Op:  "connect",
				Net: "tcp",
				Err: errors.New("connection was refused"),
			},
			wantTitle:  "Service Unavailable",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name: "syscall EHOSTUNREACH via os.SyscallError",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: syscall.EHOSTUNREACH},
			},
			wantTitle:  "Peer Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name: "syscall ENETUNREACH via os.SyscallError",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
			},
			wantTitle:  "Peer Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name: "gvisor host is unreachable",
			err: &net.OpError{
				Op:  "connect",
				Net: "tcp",
				Err: errors.New("host is unreachable"),
			},
			wantTitle:  "Peer Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name: "gvisor network is unreachable",
			err: &net.OpError{
				Op:  "connect",
				Net: "tcp",
				Err: errors.New("network is unreachable"),
			},
			wantTitle:  "Peer Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name: "standard no route to host",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: syscall.EHOSTUNREACH},
			},
			wantTitle:  "Peer Not Connected",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
		{
			name:       "unknown error falls to default",
			err:        errors.New("something unexpected"),
			wantTitle:  "Connection Error",
			wantCode:   http.StatusBadGateway,
			wantStatus: web.ErrorStatus{Proxy: true, Destination: false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, _, code, status := classifyProxyError(tt.err)
			assert.Equal(t, tt.wantTitle, title, "title")
			assert.Equal(t, tt.wantCode, code, "status code")
			assert.Equal(t, tt.wantStatus, status, "component status")
		})
	}
}

func TestStampNetBirdIdentity_NoCapturedData_StripsOnly(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdUser, "spoofed@evil.io")
	pr.In.Header.Set(headerNetBirdGroups, "admin")
	pr.Out.Header = pr.In.Header.Clone()

	rewrite(pr)

	assert.Empty(t, pr.Out.Header.Get(headerNetBirdUser),
		"client-supplied X-NetBird-User must be stripped when no captured identity is present")
	assert.Empty(t, pr.Out.Header.Get(headerNetBirdGroups),
		"client-supplied X-NetBird-Groups must be stripped when no captured identity is present")
}

func TestStampNetBirdIdentity_StampsFromCapturedData(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdUser, "spoofed@evil.io")
	pr.Out.Header = pr.In.Header.Clone()

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("alice@netbird.io")
	cd.SetUserGroups([]string{"grp-eng", "grp-ops"})
	cd.SetUserGroupNames([]string{"engineering", "operations"})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Equal(t, "alice@netbird.io", pr.Out.Header.Get(headerNetBirdUser),
		"captured email must overwrite any spoofed value")
	assert.Equal(t, "engineering,operations", pr.Out.Header.Get(headerNetBirdGroups),
		"group display names must be CSV-joined in positional order")
}

// TestStampNetBirdIdentity_GroupsOnlyWhenEmailEmpty covers the
// tunnel-peer-without-user case (machine agents, unattached proxy peers).
// The proxy must still stamp the peer's groups so downstream services can
// authorise, but X-NetBird-User stays unset — only its inbound stripping
// must happen.
func TestStampNetBirdIdentity_GroupsOnlyWhenEmailEmpty(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdUser, "spoofed@evil.io")
	pr.Out.Header = pr.In.Header.Clone()

	cd := NewCapturedData("req-1")
	cd.SetUserGroups([]string{"grp-machines"})
	cd.SetUserGroupNames([]string{"machines"})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Empty(t, pr.Out.Header.Get(headerNetBirdUser),
		"X-NetBird-User must remain unset when CapturedData carries no email")
	assert.Equal(t, "machines", pr.Out.Header.Get(headerNetBirdGroups),
		"groups must still be stamped for peers without a user identity")
}

// TestStampNetBirdIdentity_EmailOnlyWhenGroupsEmpty covers the symmetric
// case: identity-resolved user without resolved group memberships.
func TestStampNetBirdIdentity_EmailOnlyWhenGroupsEmpty(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdGroups, "spoofed-admin")
	pr.Out.Header = pr.In.Header.Clone()

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("carol@netbird.io")

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Equal(t, "carol@netbird.io", pr.Out.Header.Get(headerNetBirdUser),
		"email must be stamped even when no groups are captured")
	assert.Empty(t, pr.Out.Header.Get(headerNetBirdGroups),
		"X-NetBird-Groups must remain unset when CapturedData carries no groups")
}

func TestStampNetBirdIdentity_FallsBackToGroupIDsWhenNameMissing(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("bob@netbird.io")
	cd.SetUserGroups([]string{"grp-a", "grp-b", "grp-c"})
	// "grp-b" gets an explicit empty-string display name (not just a
	// shorter slice). Both gap shapes must fall back to the id.
	cd.SetUserGroupNames([]string{"alpha", "", ""})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Equal(t, "alpha,grp-b,grp-c", pr.Out.Header.Get(headerNetBirdGroups),
		"empty-string and out-of-range name slots must both fall back to the group id")
}

// TestStampNetBirdIdentity_DropsLabelsWithComma covers the
// comma-separator constraint: a group display name that itself contains
// a comma is dropped from the header (rather than corrupting the list),
// and the remaining labels are stamped.
func TestStampNetBirdIdentity_DropsLabelsWithComma(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("alice@netbird.io")
	cd.SetUserGroups([]string{"grp-a", "grp-b", "grp-c"})
	cd.SetUserGroupNames([]string{"engineering", "EU, EMEA", "operations"})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Equal(t, "engineering,operations", pr.Out.Header.Get(headerNetBirdGroups),
		"group label with embedded comma must be dropped, remaining labels stamped")
}

// TestStampNetBirdIdentity_RejectsControlCharsInEmail covers the
// header-injection defence: an email value containing CR/LF/control
// chars is omitted entirely (not partially stamped) so the upstream
// request stays well-formed and no header injection is possible.
func TestStampNetBirdIdentity_RejectsControlCharsInEmail(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdUser, "spoofed@evil.io")
	pr.Out.Header = pr.In.Header.Clone()

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("alice@netbird.io\r\nX-Admin: yes")
	cd.SetUserGroups([]string{"grp-a"})
	cd.SetUserGroupNames([]string{"engineering"})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Empty(t, pr.Out.Header.Get(headerNetBirdUser),
		"email with CR/LF must be dropped, not partially stamped")
	assert.Equal(t, "engineering", pr.Out.Header.Get(headerNetBirdGroups),
		"groups remain stampable even when email is invalid")
}

// TestStampNetBirdIdentity_RejectsControlCharsInGroup covers the
// per-label defence: a group name with a control char is silently
// dropped, the rest are stamped.
func TestStampNetBirdIdentity_RejectsControlCharsInGroup(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("alice@netbird.io")
	cd.SetUserGroups([]string{"grp-a", "grp-b"})
	cd.SetUserGroupNames([]string{"engineering\r\nsneaky", "operations"})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Equal(t, "operations", pr.Out.Header.Get(headerNetBirdGroups),
		"group label with control char must be dropped, valid ones kept")
}

// TestStampNetBirdIdentity_OmitsGroupsHeaderWhenAllInvalid covers the
// edge case where every group label is rejected: the header must not be
// set at all (rather than set to an empty string).
func TestStampNetBirdIdentity_OmitsGroupsHeaderWhenAllInvalid(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdGroups, "spoofed-admin")
	pr.Out.Header = pr.In.Header.Clone()

	cd := NewCapturedData("req-1")
	cd.SetUserEmail("alice@netbird.io")
	cd.SetUserGroups([]string{"grp-a", "grp-b"})
	cd.SetUserGroupNames([]string{"with,comma", "with\nbreak"})

	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	_, present := pr.Out.Header[http.CanonicalHeaderKey(headerNetBirdGroups)]
	assert.False(t, present,
		"X-NetBird-Groups must not be set when every group label is rejected")
}

// nopOKTransport returns 200 for every request without dialing — used
// by the self-target-loop tests so the non-loop cases don't pay a real
// TCP-dial timeout.
type nopOKTransport struct{}

func (nopOKTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
}

// TestServeHTTP_SelfTargetLoopReturns421 covers the loop guard for
// private services: when a peer dials a service whose only target is
// the peer itself, the proxy must refuse with 421 (Misdirected
// Request) rather than round-tripping the request back over WG to
// the same peer.
func TestServeHTTP_SelfTargetLoopReturns421(t *testing.T) {
	rp := NewReverseProxy(nopOKTransport{}, "auto", nil, nil)
	rp.AddMapping(Mapping{
		ID:        "svc-1",
		AccountID: "acct-1",
		Host:      "private.svc",
		Paths: map[string]*PathTarget{
			"/": {
				URL: &url.URL{Scheme: "http", Host: "100.64.0.5:8080"},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://private.svc/", nil)
	req.Host = "private.svc"
	req.RemoteAddr = "100.64.0.5:55555"
	req = req.WithContext(types.WithOverlayOrigin(req.Context()))
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMisdirectedRequest, rec.Code,
		"a peer dialing a service whose target is itself must get 421")
}

// TestServeHTTP_SelfTargetLoop_NonOverlayRequestPassesThrough verifies
// the guard is scoped to overlay-origin requests. A public-listener
// request that happens to share a source IP with the target host must
// not be misinterpreted as a loop — the gating relies on the inbound
// marker being attached only by the per-account overlay listener.
func TestServeHTTP_SelfTargetLoop_NonOverlayRequestPassesThrough(t *testing.T) {
	rp := NewReverseProxy(nopOKTransport{}, "auto", nil, nil)
	rp.AddMapping(Mapping{
		ID:        "svc-1",
		AccountID: "acct-1",
		Host:      "public.svc",
		Paths: map[string]*PathTarget{
			"/": {
				URL: &url.URL{Scheme: "http", Host: "100.64.0.5:8080"},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://public.svc/", nil)
	req.Host = "public.svc"
	req.RemoteAddr = "100.64.0.5:55555"
	// No WithOverlayOrigin → the guard must not fire.
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusMisdirectedRequest, rec.Code,
		"a non-overlay request with a colliding source IP must not be flagged as a loop")
}

// TestServeHTTP_SelfTargetLoop_OverlayDifferentIPPassesThrough confirms
// that overlay-origin requests with a source IP that does *not* match
// the target host are forwarded normally.
func TestServeHTTP_SelfTargetLoop_OverlayDifferentIPPassesThrough(t *testing.T) {
	rp := NewReverseProxy(nopOKTransport{}, "auto", nil, nil)
	rp.AddMapping(Mapping{
		ID:        "svc-1",
		AccountID: "acct-1",
		Host:      "private.svc",
		Paths: map[string]*PathTarget{
			"/": {
				URL: &url.URL{Scheme: "http", Host: "100.64.0.5:8080"},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://private.svc/", nil)
	req.Host = "private.svc"
	req.RemoteAddr = "100.64.0.99:55555" // different from the target
	req = req.WithContext(types.WithOverlayOrigin(req.Context()))
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusMisdirectedRequest, rec.Code,
		"overlay request with a non-matching source IP must not be flagged as a loop")
}

// TestStampNetBirdIdentity_CapturedDataPresentButEmpty covers requests
// that carry CapturedData with no identity fields populated (e.g. the
// auth middleware ran but the request didn't authenticate). Both
// headers must be cleared and neither stamped.
func TestStampNetBirdIdentity_CapturedDataPresentButEmpty(t *testing.T) {
	target, _ := url.Parse("http://backend.internal:8080")
	p := &ReverseProxy{forwardedProto: "auto"}
	rewrite := p.rewriteFunc(target, "", false, PathRewriteDefault, nil, nil)

	pr := newProxyRequest(t, "http://example.com/", "203.0.113.50:9999")
	pr.In.Header.Set(headerNetBirdUser, "spoofed@evil.io")
	pr.In.Header.Set(headerNetBirdGroups, "spoofed-admin")
	pr.Out.Header = pr.In.Header.Clone()

	cd := NewCapturedData("req-1")
	pr.In = pr.In.WithContext(WithCapturedData(pr.In.Context(), cd))

	rewrite(pr)

	assert.Empty(t, pr.Out.Header.Get(headerNetBirdUser),
		"X-NetBird-User must be stripped when CapturedData has no email")
	assert.Empty(t, pr.Out.Header.Get(headerNetBirdGroups),
		"X-NetBird-Groups must be stripped when CapturedData has no groups")
}

// TestBuildRequestInput_PropagatesIdentityAndGroups locks the final wiring link
// between auth and the middleware chain: CapturedData identity (user, groups,
// auth method, client IP) and the target's AgentNetwork flag must land on the
// middleware Input the chain runs against. If UserGroups stops flowing here,
// llm_router denies every request with no_authorised_provider.
func TestBuildRequestInput_PropagatesIdentityAndGroups(t *testing.T) {
	cd := NewCapturedData("req-123")
	cd.SetUserID("user-1")
	cd.SetUserEmail("user@example.com")
	cd.SetUserGroups([]string{"grp-admins", "grp-users"})
	cd.SetUserGroupNames([]string{"Admins", "Users"})
	cd.SetAuthMethod("oidc")
	cd.SetClientIP(netip.MustParseAddr("100.90.1.14"))

	r := httptest.NewRequest(http.MethodPost, "http://agent.example.com/v1/chat/completions", nil)
	r.Header.Set("Content-Type", "application/json")

	result := targetResult{
		target:      &PathTarget{AgentNetwork: true},
		matchedPath: "/",
		serviceID:   types.ServiceID("svc-1"),
		accountID:   types.AccountID("acct-1"),
	}

	body := []byte(`{"model":"gpt-5.4"}`)
	in := buildRequestInput(r, result, cd, body, false, int64(len(body)))

	require.NotNil(t, in, "buildRequestInput must return an envelope")
	assert.Equal(t, middleware.SlotOnRequest, in.Slot, "request input runs in the on-request slot")
	assert.Equal(t, "svc-1", in.ServiceID, "service id must propagate")
	assert.Equal(t, "acct-1", in.AccountID, "account id must propagate")
	assert.Equal(t, "user-1", in.UserID, "user id must propagate")
	assert.Equal(t, "user@example.com", in.UserEmail, "user email must propagate")
	assert.Equal(t, []string{"grp-admins", "grp-users"}, in.UserGroups,
		"CapturedData groups MUST reach the middleware Input — llm_router authorises against this")
	assert.Equal(t, []string{"Admins", "Users"}, in.UserGroupNames, "group names must propagate")
	assert.Equal(t, "oidc", in.AuthMethod, "auth method must propagate")
	assert.Equal(t, "100.90.1.14", in.SourceIP, "client IP must propagate")
	assert.True(t, in.AgentNetwork, "agent-network target flag must reach the Input")
	assert.Equal(t, body, in.Body, "captured body must reach the Input")
}
