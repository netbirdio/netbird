package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/netbirdio/netbird/proxy/internal/certwatch"
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

type metricsRecorder interface {
	RecordCertificateIssuance(duration time.Duration)
}

// wildcardEntry maps a domain suffix (e.g. ".example.com") to a certwatch
// watcher that hot-reloads the corresponding wildcard certificate from disk.
type wildcardEntry struct {
	suffix  string // e.g. ".example.com"
	pattern string // e.g. "*.example.com"
	watcher *certwatch.Watcher
}

// ManagerConfig holds the configuration values for the ACME certificate manager.
type ManagerConfig struct {
	// CertDir is the directory used for caching ACME certificates.
	CertDir string
	// ACMEURL is the ACME directory URL (e.g. Let's Encrypt).
	ACMEURL string
	// EABKID and EABHMACKey are optional External Account Binding credentials
	// required by some CAs (e.g. ZeroSSL). EABHMACKey is the base64
	// URL-encoded string provided by the CA.
	EABKID     string
	EABHMACKey string
	// LockMethod controls the cross-replica coordination strategy.
	LockMethod CertLockMethod
	// WildcardDir is an optional path to a directory containing wildcard
	// certificate pairs (<name>.crt / <name>.key). Wildcard patterns are
	// extracted from the certificates' SAN lists. Domains matching a
	// wildcard are served from disk; all others go through ACME.
	WildcardDir string
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

	// wildcards holds all loaded wildcard certificates, keyed by suffix.
	wildcards []wildcardEntry

	certNotifier certificateNotifier
	logger       *log.Logger
	metrics      metricsRecorder
}

// NewManager creates a new ACME certificate manager.
func NewManager(cfg ManagerConfig, notifier certificateNotifier, logger *log.Logger, metrics metricsRecorder) (*Manager, error) {
	if logger == nil {
		logger = log.StandardLogger()
	}
	mgr := &Manager{
		certDir:      cfg.CertDir,
		locker:       newCertLocker(cfg.LockMethod, cfg.CertDir, logger),
		domains:      make(map[domain.Domain]*domainInfo),
		certNotifier: notifier,
		logger:       logger,
		metrics:      metrics,
	}

	if cfg.WildcardDir != "" {
		entries, err := loadWildcardDir(cfg.WildcardDir, logger)
		if err != nil {
			return nil, fmt.Errorf("load wildcard certificates from %q: %w", cfg.WildcardDir, err)
		}
		mgr.wildcards = entries
	}

	var eab *acme.ExternalAccountBinding
	if cfg.EABKID != "" && cfg.EABHMACKey != "" {
		decodedKey, err := base64.RawURLEncoding.DecodeString(cfg.EABHMACKey)
		if err != nil {
			logger.Errorf("failed to decode EAB HMAC key: %v", err)
		} else {
			eab = &acme.ExternalAccountBinding{
				KID: cfg.EABKID,
				Key: decodedKey,
			}
			logger.Infof("configured External Account Binding with KID: %s", cfg.EABKID)
		}
	}

	mgr.Manager = &autocert.Manager{
		Prompt:                 autocert.AcceptTOS,
		HostPolicy:             mgr.hostPolicy,
		Cache:                  autocert.DirCache(cfg.CertDir),
		ExternalAccountBinding: eab,
		Client: &acme.Client{
			DirectoryURL: cfg.ACMEURL,
		},
	}
	return mgr, nil
}

// WatchWildcards starts watching all wildcard certificate files for changes.
// It blocks until ctx is cancelled. It is a no-op if no wildcards are loaded.
func (mgr *Manager) WatchWildcards(ctx context.Context) {
	if len(mgr.wildcards) == 0 {
		return
	}
	seen := make(map[*certwatch.Watcher]struct{})
	var wg sync.WaitGroup
	for i := range mgr.wildcards {
		w := mgr.wildcards[i].watcher
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Watch(ctx)
		}()
	}
	wg.Wait()
}

// loadWildcardDir scans dir for .crt files, pairs each with a matching .key
// file, loads them, and extracts wildcard SANs (*.example.com) to build
// the suffix lookup entries.
func loadWildcardDir(dir string, logger *log.Logger) ([]wildcardEntry, error) {
	crtFiles, err := filepath.Glob(filepath.Join(dir, "*.crt"))
	if err != nil {
		return nil, fmt.Errorf("glob certificate files: %w", err)
	}

	if len(crtFiles) == 0 {
		return nil, fmt.Errorf("no .crt files found in %s", dir)
	}

	var entries []wildcardEntry

	for _, crtPath := range crtFiles {
		base := strings.TrimSuffix(filepath.Base(crtPath), ".crt")
		keyPath := filepath.Join(dir, base+".key")
		if _, err := os.Stat(keyPath); err != nil {
			logger.Warnf("skipping %s: no matching key file %s", crtPath, keyPath)
			continue
		}

		watcher, err := certwatch.NewWatcher(crtPath, keyPath, logger)
		if err != nil {
			logger.Warnf("skipping %s: %v", crtPath, err)
			continue
		}

		leaf := watcher.Leaf()
		if leaf == nil {
			logger.Warnf("skipping %s: no parsed leaf certificate", crtPath)
			continue
		}

		for _, san := range leaf.DNSNames {
			suffix, ok := parseWildcard(san)
			if !ok {
				continue
			}
			entries = append(entries, wildcardEntry{
				suffix:  suffix,
				pattern: san,
				watcher: watcher,
			})
			logger.Infof("wildcard certificate loaded: %s (from %s)", san, filepath.Base(crtPath))
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no wildcard SANs (*.example.com) found in certificates in %s", dir)
	}

	return entries, nil
}

// parseWildcard validates a wildcard domain pattern like "*.example.com"
// and returns the suffix ".example.com" for matching.
func parseWildcard(pattern string) (suffix string, ok bool) {
	if !strings.HasPrefix(pattern, "*.") {
		return "", false
	}
	parent := pattern[1:] // ".example.com"
	if strings.Count(parent, ".") < 1 {
		return "", false
	}
	return strings.ToLower(parent), true
}

// findWildcardEntry returns the wildcard entry that covers host, or nil.
func (mgr *Manager) findWildcardEntry(host string) *wildcardEntry {
	if len(mgr.wildcards) == 0 {
		return nil
	}
	host = strings.ToLower(host)
	for i := range mgr.wildcards {
		e := &mgr.wildcards[i]
		if !strings.HasSuffix(host, e.suffix) {
			continue
		}
		// Single-level match: prefix before suffix must have no dots.
		prefix := strings.TrimSuffix(host, e.suffix)
		if len(prefix) > 0 && !strings.Contains(prefix, ".") {
			return e
		}
	}
	return nil
}

// WildcardPatterns returns the wildcard patterns that are currently loaded.
func (mgr *Manager) WildcardPatterns() []string {
	patterns := make([]string, len(mgr.wildcards))
	for i, e := range mgr.wildcards {
		patterns[i] = e.pattern
	}
	slices.Sort(patterns)
	return patterns
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

// GetCertificate returns the TLS certificate for the given ClientHello.
// If the requested domain matches a loaded wildcard, the static wildcard
// certificate is returned. Otherwise, the ACME autocert manager handles
// the request.
func (mgr *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if e := mgr.findWildcardEntry(hello.ServerName); e != nil {
		return e.watcher.GetCertificate(hello)
	}
	return mgr.Manager.GetCertificate(hello)
}

// AddDomain registers a domain for certificate management. Domains that
// match a loaded wildcard are marked ready immediately (they use the
// static wildcard certificate). All other domains go through ACME prefetch.
func (mgr *Manager) AddDomain(d domain.Domain, accountID, serviceID string) {
	name := d.PunycodeString()
	if e := mgr.findWildcardEntry(name); e != nil {
		mgr.mu.Lock()
		mgr.domains[d] = &domainInfo{
			accountID: accountID,
			serviceID: serviceID,
			state:     domainReady,
		}
		mgr.mu.Unlock()
		mgr.logger.Debugf("domain %q matches wildcard %q, using static certificate", name, e.pattern)

		if mgr.certNotifier != nil {
			if err := mgr.certNotifier.NotifyCertificateIssued(context.Background(), accountID, serviceID, name); err != nil {
				mgr.logger.Warnf("notify certificate ready for domain %q: %v", name, err)
			}
		}
		return
	}

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
// ACME and periodic disk reads race; whichever produces a valid certificate
// first wins. This handles cases where locking is unreliable and another
// replica already wrote the cert to the shared cache.
func (mgr *Manager) prefetchCertificate(d domain.Domain) {
	time.Sleep(time.Duration(rand.IntN(200)) * time.Millisecond)

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

	if cert, err := mgr.readCertFromDisk(ctx, name); err == nil {
		mgr.logger.Infof("certificate for domain %q already on disk, skipping ACME", name)
		mgr.recordAndNotify(ctx, d, name, cert, 0)
		return
	}

	// Run ACME in a goroutine so we can race it against periodic disk reads.
	// autocert uses its own internal context and cannot be cancelled externally.
	type acmeResult struct {
		cert *tls.Certificate
		err  error
	}
	acmeCh := make(chan acmeResult, 1)
	hello := &tls.ClientHelloInfo{ServerName: name, Conn: &dummyConn{ctx: ctx}}
	go func() {
		cert, err := mgr.GetCertificate(hello)
		acmeCh <- acmeResult{cert, err}
	}()

	start := time.Now()
	diskTicker := time.NewTicker(5 * time.Second)
	defer diskTicker.Stop()

	for {
		select {
		case res := <-acmeCh:
			elapsed := time.Since(start)
			if res.err != nil {
				mgr.logger.Warnf("prefetch certificate for domain %q in %s: %v", name, elapsed.String(), res.err)
				mgr.setDomainState(d, domainFailed, res.err.Error())
				return
			}
			mgr.recordAndNotify(ctx, d, name, res.cert, elapsed)
			return

		case <-diskTicker.C:
			cert, err := mgr.readCertFromDisk(context.Background(), name)
			if err != nil {
				continue
			}
			mgr.logger.Infof("certificate for domain %q appeared on disk after %s", name, time.Since(start).Round(time.Millisecond))
			// Drain the ACME goroutine before marking ready — autocert holds
			// an internal write lock on certState while ACME is in flight.
			go func() {
				select {
				case <-acmeCh:
				default:
				}
				mgr.recordAndNotify(context.Background(), d, name, cert, 0)
			}()
			return

		case <-ctx.Done():
			mgr.logger.Warnf("prefetch certificate for domain %q timed out", name)
			mgr.setDomainState(d, domainFailed, ctx.Err().Error())
			return
		}
	}
}

// readCertFromDisk reads and parses a certificate directly from the autocert
// DirCache, bypassing autocert's internal certState mutex. Safe to call
// concurrently with an in-flight ACME request for the same domain.
func (mgr *Manager) readCertFromDisk(ctx context.Context, name string) (*tls.Certificate, error) {
	if mgr.Cache == nil {
		return nil, fmt.Errorf("no cache configured")
	}
	data, err := mgr.Cache.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	privBlock, certsPEM := pem.Decode(data)
	if privBlock == nil || !strings.Contains(privBlock.Type, "PRIVATE") {
		return nil, fmt.Errorf("no private key in cache for %q", name)
	}
	cert, err := tls.X509KeyPair(certsPEM, pem.EncodeToMemory(privBlock))
	if err != nil {
		return nil, fmt.Errorf("parse cached certificate for %q: %w", name, err)
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf for %q: %w", name, err)
		}
		if time.Now().After(leaf.NotAfter) {
			return nil, fmt.Errorf("cached certificate for %q expired at %s", name, leaf.NotAfter)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// recordAndNotify records metrics, marks the domain ready, logs cert details,
// and notifies the cert notifier.
func (mgr *Manager) recordAndNotify(ctx context.Context, d domain.Domain, name string, cert *tls.Certificate, elapsed time.Duration) {
	if elapsed > 0 && mgr.metrics != nil {
		mgr.metrics.RecordCertificateIssuance(elapsed)
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
