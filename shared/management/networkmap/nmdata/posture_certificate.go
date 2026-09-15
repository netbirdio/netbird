package nmdata

import (
	"time"

	"github.com/netbirdio/netbird/shared/management/certposture"
)

// CertificateCheck is the slim twin of posture.CertificateCheck.
type CertificateCheck struct {
	CACertificates []string
}

func (c *CertificateCheck) check(peer *Peer) (bool, error) {
	return certposture.AnyChainMatchesCAs(peer.Meta.Certificates, c.CACertificates, time.Now()), nil
}
