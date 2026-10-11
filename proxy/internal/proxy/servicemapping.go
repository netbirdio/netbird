package proxy

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
	"github.com/netbirdio/netbird/proxy/internal/netutil"
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
	// DirectUpstream selects the stdlib HTTP transport (host network stack)
	// over the embedded NetBird WireGuard client when forwarding requests
	// to this target. Default false → embedded client (existing behaviour).
	DirectUpstream bool
	// Middlewares is the validated per-target middleware chain. Nil or empty
	// for non-agent-network targets, keeping them on the no-middleware fast path.
	Middlewares []middleware.Spec
	// CaptureConfig holds the per-target body-capture limits used by the
	// middleware chain. Nil for targets without body-inspecting middlewares.
	CaptureConfig *bodytap.Config
	// AgentNetwork marks this target as a synthesised agent-network target so
	// the proxy can tag access-log entries and gate agent-network behaviour.
	AgentNetwork bool
	// DisableAccessLog suppresses the per-request access-log emission for this
	// target. Defaults false so non-agent-network targets continue to log
	// unchanged. The agent-network synthesizer sets this true only when the
	// account's EnableLogCollection toggle is off.
	DisableAccessLog bool
}

// Mapping describes how a domain is routed by the HTTP reverse proxy.
type Mapping struct {
	ID               types.ServiceID
	AccountID        types.AccountID
	Host             string
	Paths            map[string]*PathTarget
	PassHostHeader   bool
	RewriteRedirects bool
	// StripAuthHeaders are header names used for header-based auth.
	// These headers are stripped from requests before forwarding.
	StripAuthHeaders []string
	// sortedPaths caches the paths sorted by length (longest first).
	sortedPaths []string
}

type targetResult struct {
	target           *PathTarget
	matchedPath      string
	serviceID        types.ServiceID
	accountID        types.AccountID
	passHostHeader   bool
	rewriteRedirects bool
	stripAuthHeaders []string
}

func (p *ReverseProxy) findTargetForRequest(req *http.Request) (targetResult, bool) {
	p.mappingsMux.RLock()
	defer p.mappingsMux.RUnlock()

	// Host is an authorization and routing key. Canonicalize it identically to
	// the management domain so case and a DNS root dot cannot select a
	// different (and potentially unprotected) route.
	host := netutil.NormalizeHost(req.Host)

	m, exists := p.mappings[host]
	if !exists {
		p.logger.Debugf("no mapping found for host: %s", host)
		return targetResult{}, false
	}

	for _, path := range m.sortedPaths {
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
				stripAuthHeaders: m.StripAuthHeaders,
			}, true
		}
	}
	p.logger.Debugf("no path match for host: %s, path: %s", host, req.URL.Path)
	return targetResult{}, false
}

// AddMapping registers a host-to-backend mapping for the reverse proxy.
func (p *ReverseProxy) AddMapping(m Mapping) {
	p.addMapping(m, false)
}

// AddMappingForService registers m without overwriting a mapping owned by a
// different service. It returns false on an ownership conflict.
func (p *ReverseProxy) AddMappingForService(m Mapping) bool {
	return p.addMapping(m, true)
}

func (p *ReverseProxy) addMapping(m Mapping, enforceOwner bool) bool {
	m.Host = netutil.NormalizeHost(m.Host)
	// Sort paths longest-first to match the most specific route first.
	paths := make([]string, 0, len(m.Paths))
	for path := range m.Paths {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j])
	})
	m.sortedPaths = paths

	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	if existing, ok := p.mappings[m.Host]; ok && enforceOwner && existing.ID != m.ID {
		return false
	}
	p.mappings[m.Host] = m
	return true
}

// RemoveMapping removes the mapping for the given host and reports whether it existed.
func (p *ReverseProxy) RemoveMapping(m Mapping) bool {
	m.Host = netutil.NormalizeHost(m.Host)
	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	existing, ok := p.mappings[m.Host]
	if !ok || (m.ID != "" && existing.ID != m.ID) {
		return false
	}
	delete(p.mappings, m.Host)
	return true
}

// MappingOwner returns the service that currently owns host.
func (p *ReverseProxy) MappingOwner(host string) (types.ServiceID, bool) {
	host = netutil.NormalizeHost(host)
	p.mappingsMux.RLock()
	defer p.mappingsMux.RUnlock()
	m, ok := p.mappings[host]
	return m.ID, ok
}
