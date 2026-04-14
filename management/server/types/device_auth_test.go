package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceCertificate(t *testing.T) {
	now := time.Now().UTC()
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(24 * time.Hour * 365)

	cert := NewDeviceCertificate("acct1", "peer1", "wg-pubkey", "12345", "-----BEGIN CERTIFICATE-----", notBefore, notAfter)

	require.NotEmpty(t, cert.ID)
	assert.Equal(t, "acct1", cert.AccountID)
	assert.Equal(t, "peer1", cert.PeerID)
	assert.Equal(t, "wg-pubkey", cert.WGPublicKey)
	assert.Equal(t, "12345", cert.Serial)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----", cert.PEM)
	assert.Equal(t, notBefore, cert.NotBefore)
	assert.Equal(t, notAfter, cert.NotAfter)
	assert.False(t, cert.Revoked)
	assert.Nil(t, cert.RevokedAt)
	assert.WithinDuration(t, now, cert.CreatedAt, time.Second)
}

func TestNewDeviceCertificate_UniqueIDs(t *testing.T) {
	a := NewDeviceCertificate("a", "p", "k", "1", "pem", time.Now(), time.Now())
	b := NewDeviceCertificate("a", "p", "k", "2", "pem", time.Now(), time.Now())
	assert.NotEqual(t, a.ID, b.ID)
}

func TestNewTrustedCA(t *testing.T) {
	now := time.Now().UTC()
	ca := NewTrustedCA("acct1", "My CA", "-----BEGIN CERTIFICATE-----")

	require.NotEmpty(t, ca.ID)
	assert.Equal(t, "acct1", ca.AccountID)
	assert.Equal(t, "My CA", ca.Name)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----", ca.PEM)
	assert.WithinDuration(t, now, ca.CreatedAt, time.Second)
}

func TestNewEnrollmentRequest(t *testing.T) {
	now := time.Now().UTC()
	req := NewEnrollmentRequest("acct1", "peer1", "wg-key", "-----BEGIN CERTIFICATE REQUEST-----", `{"os":"linux"}`)

	require.NotEmpty(t, req.ID)
	assert.Equal(t, "acct1", req.AccountID)
	assert.Equal(t, "peer1", req.PeerID)
	assert.Equal(t, "wg-key", req.WGPublicKey)
	assert.Equal(t, "-----BEGIN CERTIFICATE REQUEST-----", req.CSRPEM)
	assert.Equal(t, `{"os":"linux"}`, req.SystemInfo)
	assert.Equal(t, EnrollmentStatusPending, req.Status)
	assert.Empty(t, req.Reason)
	assert.WithinDuration(t, now, req.CreatedAt, time.Second)
	assert.WithinDuration(t, now, req.UpdatedAt, time.Second)
}

func TestEnrollmentRequest_IsActive(t *testing.T) {
	tests := []struct {
		status string
		active bool
	}{
		{EnrollmentStatusPending, true},
		{EnrollmentStatusApproved, true},
		{EnrollmentStatusRejected, false},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			req := &EnrollmentRequest{Status: tt.status}
			assert.Equal(t, tt.active, req.IsActive())
		})
	}
}

func TestEnrollmentStatus_Constants(t *testing.T) {
	assert.Equal(t, "pending", EnrollmentStatusPending)
	assert.Equal(t, "approved", EnrollmentStatusApproved)
	assert.Equal(t, "rejected", EnrollmentStatusRejected)
}
