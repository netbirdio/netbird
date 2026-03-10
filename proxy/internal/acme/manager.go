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
	"net"
	"slices"
	"strings"
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

type metricsRecorder interface {
	RecordCertificateIssuance(duration time.Duration)
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
	metrics      metricsRecorder
}

// NewManager creates a new ACME certificate manager. The certDir is used
// for caching certificates. The lockMethod controls cross-replica coordination
// strategy (see CertLockMethod constants).
// eabKID and eabHMACKey are optional External Account Binding credentials
// required for some CAs like ZeroSSL. The eabHMACKey should be the base64
// URL-encoded string provided by the CA.
func NewManager(certDir, acmeURL, eabKID, eabHMACKey string, notifier certificateNotifier, logger *log.Logger, lockMethod CertLockMethod, metrics metricsRecorder) *Manager {
	if logger == nil {
		logger = log.StandardLogger()
	}
	mgr := &Manager{
		certDir:      certDir,
		locker:       newCertLocker(lockMethod, certDir, logger),
		domains:      make(map[domain.Domain]*domainInfo),
		certNotifier: notifier,
		logger:       logger,
		metrics:      metrics,
	}

	var eab *acme.ExternalAccountBinding
	if eabKID != "" && eabHMACKey != "" {
		decodedKey, err := base64.RawURLEncoding.DecodeString(eabHMACKey)
		if err != nil {
			logger.Errorf("failed to decode EAB HMAC key: %v", err)
		} else {
			eab = &acme.ExternalAccountBinding{
				KID: eabKID,
				Key: decodedKey,
			}
			logger.Infof("configured External Account Binding with KID: %s", eabKID)
		}
	}

	mgr.Manager = &autocert.Manager{
		Prompt:                 autocert.AcceptTOS,
		HostPolicy:             mgr.hostPolicy,
		Cache:                  autocert.DirCache(certDir),
		ExternalAccountBinding: eab,
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
// duplicate ACME requests. While waiting for the lock a background goroutine
// polls disk; if another replica writes the certificate first it cancels the
// lock wait so this replica can load from disk instead. Once the lock is
// resolved, ACME and a disk-polling ticker race: whichever produces a valid
// certificate first wins and the other is abandoned.
func (mgr *Manager) prefetchCertificate(d domain.Domain) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	name := d.PunycodeString()

	if cert, err := mgr.readCertFromDisk(ctx, name); err == nil {
		mgr.logger.Infof("certificate for domain %q already on disk, skipping ACME", name)
		mgr.finalizeCert(ctx, d, name, cert, 0)
		return
	}

	// Poll disk only during the lock-wait phase. A child context lets us stop
	// the goroutine cleanly once the lock outcome is known.
	pollCtx, stopPoll := context.WithCancel(ctx)
	go mgr.pollDiskAndCancel(pollCtx, name, cancel)

	mgr.logger.Infof("acquiring cert lock for domain %q", name)
	lockStart := time.Now()
	unlock, err := mgr.locker.Lock(ctx, name)
	stopPoll() // stop poll regardless of lock outcome

	if err != nil {
		if cert, derr := mgr.readCertFromDisk(context.Background(), name); derr == nil {
			mgr.logger.Infof("certificate for domain %q appeared on disk while waiting for lock", name)
			mgr.finalizeCert(context.Background(), d, name, cert, 0)
			return
		}
		mgr.logger.Warnf("acquire cert lock for domain %q, proceeding without lock: %v", name, err)
	} else {
		mgr.logger.Infof("acquired cert lock for domain %q in %s", name, time.Since(lockStart))
		defer unlock()
	}

	if cert, err := mgr.readCertFromDisk(ctx, name); err == nil {
		mgr.logger.Infof("certificate for domain %q already on disk after lock, skipping ACME", name)
		mgr.finalizeCert(ctx, d, name, cert, 0)
		return
	}

	// Race ACME against disk polling. autocert creates its own internal
	// context so it cannot be cancelled externally; we run it in a goroutine
	// and abandon it if the disk wins. The abandoned goroutine will receive
	// orderNotReady from the CA (cert already issued) and exit on its own.
	type acmeResult struct {
		cert *tls.Certificate
		err  error
	}
	acmeCh := make(chan acmeResult, 1)
	hello := &tls.ClientHelloInfo{ServerName: name, Conn: &dummyConn{ctx: ctx}}
	go func() {
		cert, err := mgr.Manager.GetCertificate(hello)
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
				if cert, derr := mgr.readCertFromDisk(context.Background(), name); derr == nil {
					mgr.logger.Infof("ACME failed for domain %q but cert on disk, using disk cert: %v", name, res.err)
					mgr.finalizeCert(context.Background(), d, name, cert, 0)
					return
				}
				mgr.logger.Warnf("prefetch certificate for domain %q in %s: %v", name, elapsed, res.err)
				mgr.setDomainState(d, domainFailed, res.err.Error())
				return
			}
			mgr.finalizeCert(ctx, d, name, res.cert, elapsed)
			return

		case <-diskTicker.C:
			cert, err := mgr.readCertFromDisk(context.Background(), name)
			if err != nil {
				continue
			}
			mgr.logger.Infof("cert appeared on disk for domain %q after %s, disk won the race", name, time.Since(start).Round(time.Millisecond))
			// Drain the ACME goroutine before finalizing. autocert holds a
			// per-domain write lock while ACME is in flight; calling
			// finalizeCert (→ domainReady) before that lock is released would
			// let browser connections through and block them on the read lock.
			// Draining keeps the domain in domainPending (redirect active)
			// until autocert is done, then flips atomically.
			go func() {
				<-acmeCh // result is irrelevant; cert is already on disk
				mgr.finalizeCert(context.Background(), d, name, cert, 0)
			}()
			return // defer unlock() fires; above goroutine finalizes async

		case <-ctx.Done():
			mgr.logger.Warnf("prefetch certificate for domain %q timed out", name)
			mgr.setDomainState(d, domainFailed, ctx.Err().Error())
			return
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

// readCertFromDisk reads and parses the certificate for name directly from the
// autocert DirCache, bypassing autocert's internal certState mutex. This is
// safe to call even while autocert is actively running ACME for the same
// domain in another goroutine. The cert is validated (not expired, parses
// correctly) before being returned.
//
// autocert cache format: [private key PEM block][certificate chain PEM blocks...]
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
	if len(certsPEM) == 0 {
		return nil, fmt.Errorf("no certificate in cache for %q", name)
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

// pollDiskAndCancel polls the shared disk cache every 5 seconds and calls
// cancel if a valid certificate for name appears. It is intended to run as a
// goroutine only during the lock-wait phase; pass a child context so it can
// be stopped cleanly once the lock outcome is known.
func (mgr *Manager) pollDiskAndCancel(ctx context.Context, name string, cancel context.CancelFunc) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := mgr.readCertFromDisk(context.Background(), name); err == nil {
				mgr.logger.Debugf("cert detected on disk for domain %q, cancelling lock wait", name)
				cancel()
				return
			}
		}
	}
}

// finalizeCert marks the domain ready, logs cert details, records metrics if
// elapsed > 0 (i.e. the cert was issued via ACME rather than loaded from
// disk), and notifies the cert notifier.
func (mgr *Manager) finalizeCert(ctx context.Context, d domain.Domain, name string, cert *tls.Certificate, elapsed time.Duration) {
	if elapsed > 0 && mgr.metrics != nil {
		mgr.metrics.RecordCertificateIssuance(elapsed)
	}
	mgr.setDomainState(d, domainReady, "")
	now := time.Now()
	if cert != nil && cert.Leaf != nil {
		leaf := cert.Leaf
		mgr.logger.Infof("certificate for domain %q ready in %s: serial=%s SANs=%v notBefore=%s notAfter=%s now=%s",
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
