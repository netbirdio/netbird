package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type Mapping struct {
	ID        string
	AccountID string
	Host      string
	Paths     map[string]*url.URL
}

func (p *ReverseProxy) findTargetForRequest(req *http.Request) (*url.URL, string, string, bool) {
	p.mappingsMux.RLock()
	if p.mappings == nil {
		p.mappingsMux.RUnlock()
		p.mappingsMux.Lock()
		defer p.mappingsMux.Unlock()
		p.mappings = make(map[string]Mapping)
		// There cannot be any loaded Mappings as we have only just initialized.
		return nil, "", "", false
	}
	defer p.mappingsMux.RUnlock()

	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	m, exists := p.mappings[host]
	if !exists {
		return nil, "", "", false
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
			return m.Paths[path], m.ID, m.AccountID, true
		}
	}
	return nil, "", "", false
}

func (p *ReverseProxy) AddMapping(m Mapping) {
	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	if p.mappings == nil {
		p.mappings = make(map[string]Mapping)
	}
	p.mappings[m.Host] = m
}

func (p *ReverseProxy) RemoveMapping(m Mapping) {
	p.mappingsMux.Lock()
	defer p.mappingsMux.Unlock()
	delete(p.mappings, m.Host)
}
