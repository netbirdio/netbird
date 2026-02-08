package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// OID for the SCT list extension (1.3.6.1.4.1.11129.2.4.2)
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

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
	logger       *log.Logger
}

func NewManager(certDir, acmeURL string, notifier certificateNotifier, logger *log.Logger) *Manager {
	if logger == nil {
		logger = log.StandardLogger()
	}
	mgr := &Manager{
		domains: make(map[string]struct {
			accountID      string
			reverseProxyID string
		}),
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

func (mgr *Manager) hostPolicy(ctx context.Context, domain string) error {
	mgr.domainsMux.RLock()
	_, exists := mgr.domains[domain]
	mgr.domainsMux.RUnlock()
	if !exists {
		return fmt.Errorf("unknown domain %q", domain)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		Conn:       &dummyConn{ctx: ctx},
	}

	mgr.logger.Infof("prefetching certificate for domain %q", domain)
	cert, err := mgr.GetCertificate(hello)
	if err != nil {
		mgr.logger.Warnf("prefetch certificate for domain %q: %v", domain, err)
		return
	}

	now := time.Now()
	if cert != nil && cert.Leaf != nil {
		mgr.logCertificateDetails(domain, cert.Leaf, now)
	}

	mgr.logger.Infof("certificate for domain %q is ready", domain)

	mgr.domainsMux.RLock()
	info, exists := mgr.domains[domain]
	mgr.domainsMux.RUnlock()

	if exists && mgr.certNotifier != nil {
		if err := mgr.certNotifier.NotifyCertificateIssued(ctx, info.accountID, info.reverseProxyID, domain); err != nil {
			mgr.logger.Warnf("notify certificate ready for domain %q: %v", domain, err)
		}
	}
}

// logCertificateDetails logs certificate validity and SCT timestamps.
func (mgr *Manager) logCertificateDetails(domain string, cert *x509.Certificate, now time.Time) {
	mgr.logger.Infof("certificate for %q: NotBefore=%v, NotAfter=%v, now=%v",
		domain, cert.NotBefore.UTC(), cert.NotAfter.UTC(), now.UTC())

	if cert.NotBefore.After(now) {
		mgr.logger.Warnf("certificate for %q NotBefore is in the future by %v", domain, cert.NotBefore.Sub(now))
	} else {
		mgr.logger.Infof("certificate for %q NotBefore is %v in the past", domain, now.Sub(cert.NotBefore))
	}

	sctTimestamps := mgr.parseSCTTimestamps(cert)
	if len(sctTimestamps) == 0 {
		mgr.logger.Warnf("certificate for %q has no embedded SCTs", domain)
		return
	}

	for i, sctTime := range sctTimestamps {
		if sctTime.After(now) {
			mgr.logger.Warnf("certificate for %q SCT[%d] timestamp is in the future: %v (by %v)",
				domain, i, sctTime.UTC(), sctTime.Sub(now))
		} else {
			mgr.logger.Infof("certificate for %q SCT[%d] timestamp: %v (%v in the past)",
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

func (mgr *Manager) RemoveDomain(domain string) {
	mgr.domainsMux.Lock()
	defer mgr.domainsMux.Unlock()
	delete(mgr.domains, domain)
}
