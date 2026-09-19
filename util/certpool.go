package util

import (
	"crypto/x509"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

var (
	globalCertPool *x509.CertPool
	systemCertPool *x509.CertPool
	guard          sync.RWMutex
)

func init() {
	systemPool, err := x509.SystemCertPool()
	if err == nil && systemPool != nil {
		log.Debug("Using system certificate pool.")
		systemCertPool = systemPool
	} else {
		log.Debugf("System cert pool not available; falling back to embedded cert")
		systemCertPool = embeddedroots.Get()
	}

	globalCertPool = systemCertPool.Clone()
}

// SetGlobalCertPool set the new pool of CA certificates.
func SetGlobalCertPool(newCertPool *x509.CertPool) {
	if newCertPool != nil {
		newCertPool := newCertPool.Clone()
		guard.Lock()
		globalCertPool = newCertPool
		guard.Unlock()
	}
}

// GetGlobalCertPool can be used to gather the CA certificates.
// They can be modified with SetGlobalCertPool.
func GetGlobalCertPool() *x509.CertPool {
	guard.RLock()
	defer guard.RUnlock()
	return globalCertPool.Clone()
}

// GetSystemCertPool can be used to gather the unmodified system CA certificates.
func GetSystemCertPool() *x509.CertPool {
	return systemCertPool.Clone()
}
