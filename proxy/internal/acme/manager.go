package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/netbirdio/netbird/shared/management/domain"
)

// OID for the SCT list extension (1.3.6.1.4.1.11129.2.4.2)
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type certificateNotifier interface {
	NotifyCertificateIssued(ctx context.Context, accountID, serviceID, domain string) error
}

type domainState int

const (
	domainPending domainState = iota
	domainReady
	domainFailed
)

type domainInfo struct {
	accountID string
	serviceID string
	state     domainState
	err       string
}

// Manager wraps autocert.Manager with domain tracking and cross-replica
// coordination via a pluggable locking strategy. The locker prevents
// duplicate ACME requests when multiple replicas share a certificate cache.
type Manager struct {
	*autocert.Manager

	certDir string
	locker  certLocker
	mu      sync.RWMutex
	domains map[domain.Domain]*domainInfo

	certNotifier certificateNotifier
	logger       *log.Logger
}

// NewManager creates a new ACME certificate manager. The certDir is used
// for caching certificates. The lockMethod controls cross-replica
// coordination strategy (see CertLockMethod constants).
func NewManager(certDir, acmeURL string, notifier certificateNotifier, logger *log.Logger, lockMethod CertLockMethod) *Manager {
	if logger == nil {
		logger = log.StandardLogger()
	}
	mgr := &Manager{
		certDir:      certDir,
		locker:       newCertLocker(lockMethod, certDir, logger),
		domains:      make(map[domain.Domain]*domainInfo),
		certNotifier: notifier,
		logger:       logger,
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

func (mgr *Manager) hostPolicy(_ context.Context, host string) error {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	mgr.mu.RLock()
	_, exists := mgr.domains[domain.Domain(host)]
	mgr.mu.RUnlock()
	if !exists {
		return fmt.Errorf("unknown domain %q", host)
	}
	return nil
}

// AddDomain registers a domain for ACME certificate prefetching.
func (mgr *Manager) AddDomain(d domain.Domain, accountID, serviceID string) {
	mgr.mu.Lock()
	mgr.domains[d] = &domainInfo{
		accountID: accountID,
		serviceID: serviceID,
		state:     domainPending,
	}
	mgr.mu.Unlock()

	go mgr.prefetchCertificate(d)
}

// prefetchCertificate proactively triggers certificate generation for a domain.
// It acquires a distributed lock to prevent multiple replicas from issuing
// duplicate ACME requests. The second replica will block until the first
// finishes, then find the certificate in the cache.
func (mgr *Manager) prefetchCertificate(d domain.Domain) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	name := d.PunycodeString()

	mgr.logger.Infof("acquiring cert lock for domain %q", name)
	lockStart := time.Now()
	unlock, err := mgr.locker.Lock(ctx, name)
	if err != nil {
		mgr.logger.Warnf("acquire cert lock for domain %q, proceeding without lock: %v", name, err)
	} else {
		mgr.logger.Infof("acquired cert lock for domain %q in %s", name, time.Since(lockStart))
		defer unlock()
	}

	hello := &tls.ClientHelloInfo{
		ServerName: name,
		Conn:       &dummyConn{ctx: ctx},
	}

	start := time.Now()
	cert, err := mgr.GetCertificate(hello)
	elapsed := time.Since(start)
	if err != nil {
		mgr.logger.Warnf("prefetch certificate for domain %q: %v", name, err)
		mgr.setDomainState(d, domainFailed, err.Error())
		return
	}

	mgr.setDomainState(d, domainReady, "")

	now := time.Now()
	if cert != nil && cert.Leaf != nil {
		leaf := cert.Leaf
		mgr.logger.Infof("certificate for domain %q ready in %s: serial=%s SANs=%v notBefore=%s, notAfter=%s, now=%s",
			name, elapsed.Round(time.Millisecond),
			leaf.SerialNumber.Text(16),
			leaf.DNSNames,
			leaf.NotBefore.UTC().Format(time.RFC3339),
			leaf.NotAfter.UTC().Format(time.RFC3339),
			now.UTC().Format(time.RFC3339),
		)
		mgr.logCertificateDetails(name, leaf, now)
	} else {
		mgr.logger.Infof("certificate for domain %q ready in %s", name, elapsed.Round(time.Millisecond))
	}

	mgr.mu.RLock()
	info := mgr.domains[d]
	mgr.mu.RUnlock()

	if info != nil && mgr.certNotifier != nil {
		if err := mgr.certNotifier.NotifyCertificateIssued(ctx, info.accountID, info.serviceID, name); err != nil {
			mgr.logger.Warnf("notify certificate ready for domain %q: %v", name, err)
		}
	}
}

func (mgr *Manager) setDomainState(d domain.Domain, state domainState, errMsg string) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if info, ok := mgr.domains[d]; ok {
		info.state = state
		info.err = errMsg
	}
}

// logCertificateDetails logs certificate validity and SCT timestamps.
func (mgr *Manager) logCertificateDetails(domain string, cert *x509.Certificate, now time.Time) {
	if cert.NotBefore.After(now) {
		mgr.logger.Warnf("certificate for %q NotBefore is in the future by %v", domain, cert.NotBefore.Sub(now))
	}

	sctTimestamps := mgr.parseSCTTimestamps(cert)
	if len(sctTimestamps) == 0 {
		return
	}

	for i, sctTime := range sctTimestamps {
		if sctTime.After(now) {
			mgr.logger.Warnf("certificate for %q SCT[%d] timestamp is in the future: %v (by %v)",
				domain, i, sctTime.UTC(), sctTime.Sub(now))
		} else {
			mgr.logger.Debugf("certificate for %q SCT[%d] timestamp: %v (%v in the past)",
				domain, i, sctTime.UTC(), now.Sub(sctTime))
		}
	}
}

// parseSCTTimestamps extracts SCT timestamps from a certificate.
func (mgr *Manager) parseSCTTimestamps(cert *x509.Certificate) []time.Time {
	var timestamps []time.Time

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSCTList) {
			continue
		}

		// The extension value is an OCTET STRING containing the SCT list
		var sctListBytes []byte
		if _, err := asn1.Unmarshal(ext.Value, &sctListBytes); err != nil {
			mgr.logger.Debugf("failed to unmarshal SCT list outer wrapper: %v", err)
			continue
		}

		// SCT list format: 2-byte length prefix, then concatenated SCTs
		if len(sctListBytes) < 2 {
			continue
		}

		listLen := int(binary.BigEndian.Uint16(sctListBytes[:2]))
		data := sctListBytes[2:]
		if len(data) < listLen {
			continue
		}

		// Parse individual SCTs
		offset := 0
		for offset < listLen {
			if offset+2 > len(data) {
				break
			}
			sctLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2

			if offset+sctLen > len(data) {
				break
			}
			sctData := data[offset : offset+sctLen]
			offset += sctLen

			// SCT format: version (1) + log_id (32) + timestamp (8) + ...
			if len(sctData) < 41 {
				continue
			}

			// Timestamp is at offset 33 (after version + log_id), 8 bytes, milliseconds since epoch
			tsMillis := binary.BigEndian.Uint64(sctData[33:41])
			ts := time.UnixMilli(int64(tsMillis))
			timestamps = append(timestamps, ts)
		}
	}

	return timestamps
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

// RemoveDomain removes a domain from tracking.
func (mgr *Manager) RemoveDomain(d domain.Domain) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	delete(mgr.domains, d)
}

// PendingCerts returns the number of certificates currently being prefetched.
func (mgr *Manager) PendingCerts() int {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	var n int
	for _, info := range mgr.domains {
		if info.state == domainPending {
			n++
		}
	}
	return n
}

// TotalDomains returns the total number of registered domains.
func (mgr *Manager) TotalDomains() int {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return len(mgr.domains)
}

// PendingDomains returns the domain names currently being prefetched.
func (mgr *Manager) PendingDomains() []string {
	return mgr.domainsByState(domainPending)
}

// ReadyDomains returns domain names that have successfully obtained certificates.
func (mgr *Manager) ReadyDomains() []string {
	return mgr.domainsByState(domainReady)
}

// FailedDomains returns domain names that failed certificate prefetch, mapped to their error.
func (mgr *Manager) FailedDomains() map[string]string {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	result := make(map[string]string)
	for d, info := range mgr.domains {
		if info.state == domainFailed {
			result[d.PunycodeString()] = info.err
		}
	}
	return result
}

func (mgr *Manager) domainsByState(state domainState) []string {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	var domains []string
	for d, info := range mgr.domains {
		if info.state == state {
			domains = append(domains, d.PunycodeString())
		}
	}
	slices.Sort(domains)
	return domains
}
