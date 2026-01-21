package acme

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Manager struct {
	*autocert.Manager

	domainsMux sync.RWMutex
	domains    map[string]struct{}
}

func NewManager(certDir, acmeURL string) *Manager {
	mgr := &Manager{
		domains: make(map[string]struct{}),
	}
	mgr.Manager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: mgr.hostPolicy,
		Cache:      autocert.DirCache(certDir),
		Client: &acme.Client{
			DirectoryURL: acmeURL,
		},
	}
	return mgr
}

func (mgr *Manager) hostPolicy(_ context.Context, domain string) error {
	mgr.domainsMux.RLock()
	defer mgr.domainsMux.RUnlock()
	if _, exists := mgr.domains[domain]; exists {
		return nil
	}
	return fmt.Errorf("unknown domain %q", domain)
}

func (mgr *Manager) AddDomain(domain string) {
	mgr.domainsMux.Lock()
	defer mgr.domainsMux.Unlock()
	mgr.domains[domain] = struct{}{}
}

func (mgr *Manager) RemoveDomain(domain string) {
	mgr.domainsMux.Lock()
	defer mgr.domainsMux.Unlock()
	delete(mgr.domains, domain)
}
