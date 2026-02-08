package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

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
	mgr.domains[domain] = struct {
		accountID      string
		reverseProxyID string
	}{
		accountID:      accountID,
		reverseProxyID: reverseProxyID,
	}
	mgr.domainsMux.Unlock()

	go mgr.prefetchCertificate(domain)
}

// prefetchCertificate proactively triggers certificate generation for a domain.
func (mgr *Manager) prefetchCertificate(domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		Conn:       &dummyConn{ctx: ctx},
	}

	log.Infof("prefetching certificate for domain %q", domain)
	_, err := mgr.GetCertificate(hello)
	if err != nil {
		log.Warnf("prefetch certificate for domain %q: %v", domain, err)
		return
	}
	log.Infof("successfully prefetched certificate for domain %q", domain)
}

// dummyConn implements net.Conn to provide context for certificate fetching.
type dummyConn struct {
	ctx context.Context
}

func (c *dummyConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c *dummyConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *dummyConn) Close() error                       { return nil }
func (c *dummyConn) LocalAddr() net.Addr                { return nil }
func (c *dummyConn) RemoteAddr() net.Addr               { return nil }
func (c *dummyConn) SetDeadline(t time.Time) error      { return nil }
func (c *dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dummyConn) SetWriteDeadline(t time.Time) error { return nil }

func (mgr *Manager) RemoveDomain(domain string) {
	mgr.domainsMux.Lock()
	defer mgr.domainsMux.Unlock()
	delete(mgr.domains, domain)
}
