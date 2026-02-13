// Package certwatch watches TLS certificate files on disk and provides
// a hot-reloading GetCertificate callback for tls.Config.
package certwatch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPollInterval = 30 * time.Second
	debounceDelay       = 500 * time.Millisecond
)

// Watcher monitors TLS certificate files on disk and caches the loaded
// certificate in memory. It detects changes via fsnotify (with a polling
// fallback for filesystems like NFS that lack inotify support) and
// reloads the certificate pair automatically.
type Watcher struct {
	certPath string
	keyPath  string

	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate

	pollInterval time.Duration
	logger       *log.Logger
}

// NewWatcher creates a Watcher that monitors the given cert and key files.
// It performs an initial load of the certificate and returns an error
// if the initial load fails.
func NewWatcher(certPath, keyPath string, logger *log.Logger) (*Watcher, error) {
	if logger == nil {
		logger = log.StandardLogger()
	}

	w := &Watcher{
		certPath:     certPath,
		keyPath:      keyPath,
		pollInterval: defaultPollInterval,
		logger:       logger,
	}

	if err := w.reload(); err != nil {
		return nil, fmt.Errorf("initial certificate load: %w", err)
	}

	return w, nil
}

// GetCertificate returns the current in-memory certificate.
// It is safe for concurrent use and compatible with tls.Config.GetCertificate.
func (w *Watcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.cert, nil
}

// Watch starts watching for certificate file changes. It blocks until
// ctx is cancelled. It uses fsnotify for immediate detection and falls
// back to polling if fsnotify is unavailable (e.g. on NFS).
// Even with fsnotify active, a periodic poll runs as a safety net.
func (w *Watcher) Watch(ctx context.Context) {
	// Watch the parent directory rather than individual files. Some volume
	// mounts use an atomic symlink swap (..data -> timestamped dir), so
	// watching the parent directory catches the link replacement.
	certDir := filepath.Dir(w.certPath)
	keyDir := filepath.Dir(w.keyPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.logger.Warnf("fsnotify unavailable, using polling only: %v", err)
		w.pollLoop(ctx)
		return
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			w.logger.Debugf("close fsnotify watcher: %v", err)
		}
	}()

	if err := watcher.Add(certDir); err != nil {
		w.logger.Warnf("fsnotify watch on %s failed, using polling only: %v", certDir, err)
		w.pollLoop(ctx)
		return
	}

	if keyDir != certDir {
		if err := watcher.Add(keyDir); err != nil {
			w.logger.Warnf("fsnotify watch on %s failed: %v", keyDir, err)
		}
	}

	w.logger.Infof("watching certificate files in %s", certDir)
	w.fsnotifyLoop(ctx, watcher)
}

func (w *Watcher) fsnotifyLoop(ctx context.Context, watcher *fsnotify.Watcher) {
	certBase := filepath.Base(w.certPath)
	keyBase := filepath.Base(w.keyPath)

	var debounce *time.Timer
	defer func() {
		if debounce != nil {
			debounce.Stop()
		}
	}()

	// Periodic poll as a safety net for missed fsnotify events.
	pollTicker := time.NewTicker(w.pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			base := filepath.Base(event.Name)
			if !isRelevantFile(base, certBase, keyBase) {
				w.logger.Debugf("fsnotify: ignoring event %s on %s", event.Op, event.Name)
				continue
			}
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) && !event.Has(fsnotify.Rename) {
				w.logger.Debugf("fsnotify: ignoring op %s on %s", event.Op, base)
				continue
			}

			w.logger.Debugf("fsnotify: detected %s on %s, scheduling reload", event.Op, base)

			// Debounce: cert-manager may write cert and key as separate
			// operations. Wait briefly to load both at once.
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(debounceDelay, func() {
				if ctx.Err() != nil {
					return
				}
				w.tryReload()
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			w.logger.Warnf("fsnotify error: %v", err)

		case <-pollTicker.C:
			w.tryReload()
		}
	}
}

func (w *Watcher) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tryReload()
		}
	}
}

// reload loads the certificate from disk and updates the in-memory cache.
func (w *Watcher) reload() error {
	cert, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		return err
	}

	// Parse the leaf for comparison on subsequent reloads.
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}

	w.mu.Lock()
	w.cert = &cert
	w.leaf = cert.Leaf
	w.mu.Unlock()

	w.logCertDetails("loaded certificate", cert.Leaf)

	return nil
}

// tryReload attempts to reload the certificate. It skips the update
// if the certificate on disk is identical to the one in memory (same
// serial number and issuer) to avoid redundant log noise.
func (w *Watcher) tryReload() {
	cert, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		w.logger.Warnf("reload certificate: %v", err)
		return
	}

	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			w.logger.Warnf("parse reloaded leaf certificate: %v", err)
			return
		}
		cert.Leaf = leaf
	}

	w.mu.Lock()

	if w.leaf != nil && cert.Leaf != nil &&
		w.leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) == 0 &&
		w.leaf.Issuer.CommonName == cert.Leaf.Issuer.CommonName {
		w.mu.Unlock()
		return
	}

	prev := w.leaf
	w.cert = &cert
	w.leaf = cert.Leaf
	w.mu.Unlock()

	w.logCertChange(prev, cert.Leaf)
}

func (w *Watcher) logCertDetails(msg string, leaf *x509.Certificate) {
	if leaf == nil {
		w.logger.Info(msg)
		return
	}

	w.logger.Infof("%s: subject=%q serial=%s SANs=%v notAfter=%s",
		msg,
		leaf.Subject.CommonName,
		leaf.SerialNumber.Text(16),
		leaf.DNSNames,
		leaf.NotAfter.UTC().Format(time.RFC3339),
	)
}

func (w *Watcher) logCertChange(prev, next *x509.Certificate) {
	if prev == nil || next == nil {
		w.logCertDetails("certificate reloaded from disk", next)
		return
	}

	w.logger.Infof("certificate reloaded from disk: subject=%q -> %q serial=%s -> %s notAfter=%s -> %s",
		prev.Subject.CommonName, next.Subject.CommonName,
		prev.SerialNumber.Text(16), next.SerialNumber.Text(16),
		prev.NotAfter.UTC().Format(time.RFC3339), next.NotAfter.UTC().Format(time.RFC3339),
	)
}

// isRelevantFile returns true if the changed file name is one we care about.
// This includes the cert/key files themselves and the ..data symlink used
// by atomic volume mounts.
func isRelevantFile(changed, certBase, keyBase string) bool {
	return changed == certBase || changed == keyBase || changed == "..data"
}
