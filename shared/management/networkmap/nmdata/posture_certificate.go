package nmdata

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/management/certposture"
)

// CertificateCheck is the slim twin of posture.CertificateCheck.
type CertificateCheck struct {
	CACertificates []string

	rootsOnce sync.Once
	roots     *x509.CertPool
	rootsErr  error
}

func (c *CertificateCheck) check(peer *Peer) (bool, error) {
	if len(peer.Meta.Certificates) == 0 {
		return false, nil
	}
	c.rootsOnce.Do(func() {
		c.roots, c.rootsErr = certposture.ParseCAs(c.CACertificates)
	})
	if c.rootsErr != nil {
		return false, c.rootsErr
	}
	return certposture.AnyChainMatchesPool(peer.Meta.Certificates, c.roots, time.Now()), nil
}
