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
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/web"
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
		rewrite := p.rewriteFunc(target, "/heise", false)
		pr := newProxyRequest(t, "http://external.test/heise", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/heise/", pr.Out.URL.Path,
			"backend sees /heise/ because prefix is stripped then re-added by SetURL")
	})

	t.Run("subpath under prefix also preserved", func(t *testing.T) {
		target, _ := url.Parse("https://heise.de:443/heise")
		rewrite := p.rewriteFunc(target, "/heise", false)
		pr := newProxyRequest(t, "http://external.test/heise/article/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/heise/article/123", pr.Out.URL.Path,
			"subpath is preserved on top of the re-added prefix")
	})

	// What the behavior WOULD be if target URL had no path (true stripping)
	t.Run("target without path prefix gives true stripping", func(t *testing.T) {
		target, _ := url.Parse("https://heise.de:443")
		rewrite := p.rewriteFunc(target, "/heise", false)
		pr := newProxyRequest(t, "http://external.test/heise", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/", pr.Out.URL.Path,
			"without path in target URL, backend sees / (true prefix stripping)")
	})

	t.Run("target without path prefix strips and preserves subpath", func(t *testing.T) {
		target, _ := url.Parse("https://heise.de:443")
		rewrite := p.rewriteFunc(target, "/heise", false)
		pr := newProxyRequest(t, "http://external.test/heise/article/123", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/article/123", pr.Out.URL.Path,
			"without path in target URL, prefix is truly stripped")
	})

	// Root path "/" — no stripping expected
	t.Run("root path forwards full request path unchanged", func(t *testing.T) {
		target, _ := url.Parse("https://backend.example.com:443/")
		rewrite := p.rewriteFunc(target, "/", false)
		pr := newProxyRequest(t, "http://external.test/heise", "1.2.3.4:5000")

		rewrite(pr)

		assert.Equal(t, "/heise", pr.Out.URL.Path,
			"root path match must not strip anything")
	})
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
