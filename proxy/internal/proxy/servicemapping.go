package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

type Mapping struct {
	ID             string
	AccountID      types.AccountID
	Host           string
	Paths          map[string]*url.URL
	PassHostHeader bool
}

type targetResult struct {
	url            *url.URL
	serviceID      string
	accountID      types.AccountID
	passHostHeader bool
}

func (p *ReverseProxy) findTargetForRequest(req *http.Request) (targetResult, bool) {
	p.mappingsMux.RLock()
	defer p.mappingsMux.RUnlock()

	// Strip port from host if present (e.g., "external.test:8443" -> "external.test")
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	p.logger.Debugf("looking for mapping for host: %s, path: %s", host, req.URL.Path)
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
			target := m.Paths[path]
			p.logger.Debugf("matched host: %s, path: %s -> %s", host, path, target)
			return targetResult{
				url:            target,
				serviceID:      m.ID,
				accountID:      m.AccountID,
				passHostHeader: m.PassHostHeader,
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

func (p *ReverseProxy) RemoveMapping(m Mapping) {
	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	delete(p.mappings, m.Host)
}
