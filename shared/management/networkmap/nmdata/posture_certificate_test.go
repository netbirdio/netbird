package nmdata

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

func TestCertificateCheck_Check(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	otherCA := certtest.NewCA(t, "other-root")
	chain := certposture.EncodeChainPEM([]*x509.Certificate{ca.Issue(t, certtest.ECDSAKey(t), "device")})

	c := bundle(ChecksDefinition{CertificateCheck: &CertificateCheck{CACertificates: []string{ca.PEM}}})
	without := &Peer{}
	with := &Peer{Meta: PeerSystemMeta{Certificates: []string{chain}}}

	assert.False(t, c[0].Passes(without))
	assert.True(t, c[0].Passes(with))
	assert.True(t, PostureVerdictChanged(c, without, with))

	otherOnly := bundle(ChecksDefinition{CertificateCheck: &CertificateCheck{CACertificates: []string{otherCA.PEM}}})
	assert.False(t, otherOnly[0].Passes(with))
}
