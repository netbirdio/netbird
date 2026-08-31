package posture

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

func TestCertificateCheck_Check(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	otherCA := certtest.NewCA(t, "other-root")
	chain := certposture.EncodeChainPEM([]*x509.Certificate{ca.Issue(t, certtest.ECDSAKey(t), "device")})

	tests := []struct {
		name         string
		certificates []string
		cas          []string
		want         bool
	}{
		{"chains to configured CA", []string{chain}, []string{ca.PEM}, true},
		{"one of several CAs matches", []string{chain}, []string{otherCA.PEM, ca.PEM}, true},
		{"unrelated CA", []string{chain}, []string{otherCA.PEM}, false},
		{"no certificates proven", nil, []string{ca.PEM}, false},
		{"garbage entry does not hide a valid one", []string{"garbage", chain}, []string{ca.PEM}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := CertificateCheck{CACertificates: tt.cas}
			got, err := check.Check(context.Background(), peer.Peer{Meta: peer.PeerSystemMeta{Certificates: tt.certificates}})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCertificateCheck_Validate(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")

	assert.Error(t, (&CertificateCheck{}).Validate())
	assert.Error(t, (&CertificateCheck{CACertificates: []string{"not a pem"}}).Validate())
	assert.NoError(t, (&CertificateCheck{CACertificates: []string{ca.PEM}}).Validate())
}

func TestChecks_CertificateCheckRegistered(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	checks := &Checks{Name: "cert", Checks: ChecksDefinition{CertificateCheck: &CertificateCheck{CACertificates: []string{ca.PEM}}}}

	require.NoError(t, checks.Validate())
	require.Len(t, checks.GetChecks(), 1)
	assert.Equal(t, CertificateCheckName, checks.GetChecks()[0].Name())

	copied := checks.Copy()
	checks.Checks.CertificateCheck.CACertificates[0] = "mutated"
	assert.Equal(t, ca.PEM, copied.Checks.CertificateCheck.CACertificates[0])

	api := checks.ToAPIResponse()
	require.NotNil(t, api.Checks.CertificateCheck)
	roundTrip, err := NewChecksFromAPIPostureCheck(*api)
	require.NoError(t, err)
	assert.Equal(t, checks.Checks.CertificateCheck.CACertificates, roundTrip.Checks.CertificateCheck.CACertificates)
}
