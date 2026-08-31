package posture

import (
	"context"
	"fmt"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/certposture"
)

// CertificateCheck passes when the peer holds a certificate, proven at meta ingestion,
// that chains to one of the configured PEM encoded CA certificates.
type CertificateCheck struct {
	CACertificates []string
}

var _ Check = (*CertificateCheck)(nil)

func (c *CertificateCheck) Check(_ context.Context, peer nbpeer.Peer) (bool, error) {
	return certposture.AnyChainMatchesCAs(peer.Meta.Certificates, c.CACertificates, time.Now()), nil
}

func (c *CertificateCheck) Name() string {
	return CertificateCheckName
}

func (c *CertificateCheck) Validate() error {
	if len(c.CACertificates) == 0 {
		return fmt.Errorf("%s ca certificates shouldn't be empty", c.Name())
	}
	if _, err := certposture.ParseCAs(c.CACertificates); err != nil {
		return fmt.Errorf("%s: %w", c.Name(), err)
	}
	return nil
}
