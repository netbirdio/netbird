package acme

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type certificateNotifier interface {
	NotifyCertificateIssued(ctx context.Context, accountID, reverseProxyID, domain string) error
}

type Manager struct {
	*autocert.Manager

	domainsMux sync.RWMutex
	domains    map[string]struct {
		accountID      string
		reverseProxyID string
	}

	certNotifier certificateNotifier
}

func NewManager(certDir, acmeURL string, notifier certificateNotifier) *Manager {
	mgr := &Manager{
		domains: make(map[string]struct {
			accountID      string
			reverseProxyID string
		}),
		certNotifier: notifier,
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

func (mgr *Manager) hostPolicy(ctx context.Context, domain string) error {
	mgr.domainsMux.RLock()
	info, exists := mgr.domains[domain]
	mgr.domainsMux.RUnlock()
	if !exists {
		return fmt.Errorf("unknown domain %q", domain)
	}

	if mgr.certNotifier != nil {
		if err := mgr.certNotifier.NotifyCertificateIssued(ctx, info.accountID, info.reverseProxyID, domain); err != nil {
			log.Warnf("failed to notify certificate issued for domain %q: %v", domain, err)
		}
	}

	return nil
}

func (mgr *Manager) AddDomain(domain, accountID, reverseProxyID string) {
	mgr.domainsMux.Lock()
	defer mgr.domainsMux.Unlock()
	mgr.domains[domain] = struct {
		accountID      string
		reverseProxyID string
	}{
		accountID:      accountID,
		reverseProxyID: reverseProxyID,
	}
}

func (mgr *Manager) RemoveDomain(domain string) {
	mgr.domainsMux.Lock()
	defer mgr.domainsMux.Unlock()
	delete(mgr.domains, domain)
}
