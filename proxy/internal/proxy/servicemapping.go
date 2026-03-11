package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// PathRewriteMode controls how the request path is rewritten before forwarding.
type PathRewriteMode int

const (
	// PathRewriteDefault strips the matched prefix and joins with the target path.
	PathRewriteDefault PathRewriteMode = iota
	// PathRewritePreserve keeps the full original request path as-is.
	PathRewritePreserve
)

// PathTarget holds a backend URL and per-target behavioral options.
type PathTarget struct {
	URL            *url.URL
	SkipTLSVerify  bool
	RequestTimeout time.Duration
	PathRewrite    PathRewriteMode
	CustomHeaders  map[string]string
}

// Mapping describes how a domain is routed by the HTTP reverse proxy.
type Mapping struct {
	ID               types.ServiceID
	AccountID        types.AccountID
	Host             string
	Paths            map[string]*PathTarget
	PassHostHeader   bool
	RewriteRedirects bool
}

type targetResult struct {
	target           *PathTarget
	matchedPath      string
	serviceID        types.ServiceID
	accountID        types.AccountID
	passHostHeader   bool
	rewriteRedirects bool
}

func (p *ReverseProxy) findTargetForRequest(req *http.Request) (targetResult, bool) {
	p.mappingsMux.RLock()
	defer p.mappingsMux.RUnlock()

	// Strip port from host if present (e.g., "external.test:8443" -> "external.test")
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	m, exists := p.mappings[host]
	if !exists {
		p.logger.Debugf("no mapping found for host: %s", host)
		return targetResult{}, false
	}

	// Sort paths by length (longest first) in a naive attempt to match the most specific route first.
	paths := make([]string, 0, len(m.Paths))
	for path := range m.Paths {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j])
	})

	for _, path := range paths {
		if strings.HasPrefix(req.URL.Path, path) {
			pt := m.Paths[path]
			if pt == nil || pt.URL == nil {
				p.logger.Warnf("invalid mapping for host: %s, path: %s (nil target)", host, path)
				continue
			}
			p.logger.Debugf("matched host: %s, path: %s -> %s", host, path, pt.URL)
			return targetResult{
				target:           pt,
				matchedPath:      path,
				serviceID:        m.ID,
				accountID:        m.AccountID,
				passHostHeader:   m.PassHostHeader,
				rewriteRedirects: m.RewriteRedirects,
			}, true
		}
	}
	p.logger.Debugf("no path match for host: %s, path: %s", host, req.URL.Path)
	return targetResult{}, false
}

func (p *ReverseProxy) AddMapping(m Mapping) {
	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	p.mappings[m.Host] = m
}

// RemoveMapping removes the mapping for the given host and reports whether it existed.
func (p *ReverseProxy) RemoveMapping(m Mapping) bool {
	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	if _, ok := p.mappings[m.Host]; !ok {
		return false
	}
	delete(p.mappings, m.Host)
	return true
}
