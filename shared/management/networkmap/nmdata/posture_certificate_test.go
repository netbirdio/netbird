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

func TestCertificateCheck_ReusesParsedCAs(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	chain := certposture.EncodeChainPEM([]*x509.Certificate{ca.Issue(t, certtest.ECDSAKey(t), "device")})
	with := &Peer{Meta: PeerSystemMeta{Certificates: []string{chain}}}

	check := &CertificateCheck{CACertificates: []string{ca.PEM}}
	for range 3 {
		valid, err := check.check(with)
		assert.NoError(t, err)
		assert.True(t, valid)
	}

	invalid := &CertificateCheck{CACertificates: []string{"not a pem"}}
	for range 2 {
		valid, err := invalid.check(with)
		assert.ErrorIs(t, err, certposture.ErrNoCertificateInPEM)
		assert.False(t, valid)
	}

	valid, err := invalid.check(&Peer{})
	assert.NoError(t, err)
	assert.False(t, valid, "a peer without certificates fails before the CAs are parsed")
}
