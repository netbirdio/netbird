package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCAStore struct {
	caCerts      []*CACertificate
	issuedCerts  []*IssuedCertificate
	issuanceLogs []*CertIssuanceLog
}

func newMockCAStore() *mockCAStore {
	return &mockCAStore{}
}

func (m *mockCAStore) CreateCACertificate(_ context.Context, ca *CACertificate) error {
	m.caCerts = append(m.caCerts, ca)
	return nil
}

func (m *mockCAStore) GetCACertificateByID(_ context.Context, accountID, caID string) (*CACertificate, error) {
	for _, c := range m.caCerts {
		if c.AccountID == accountID && c.ID == caID {
			return c, nil
		}
	}
	return nil, fmt.Errorf("CA not found")
}

func (m *mockCAStore) GetActiveCACertificates(_ context.Context, accountID string) ([]*CACertificate, error) {
	var active []*CACertificate
	for _, c := range m.caCerts {
		if c.AccountID == accountID && c.IsActive {
			active = append(active, c)
		}
	}
	return active, nil
}

func (m *mockCAStore) DeactivateCACertificate(_ context.Context, accountID, caID string) error {
	for _, c := range m.caCerts {
		if c.AccountID == accountID && c.ID == caID {
			c.IsActive = false
			return nil
		}
	}
	return fmt.Errorf("CA not found")
}

func (m *mockCAStore) CreateIssuedCertificate(_ context.Context, cert *IssuedCertificate) error {
	m.issuedCerts = append(m.issuedCerts, cert)
	return nil
}

func (m *mockCAStore) GetIssuedCertificates(_ context.Context, accountID string) ([]*IssuedCertificate, error) {
	var certs []*IssuedCertificate
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func (m *mockCAStore) GetIssuedCertificatesByPeer(_ context.Context, accountID, peerID string) ([]*IssuedCertificate, error) {
	var certs []*IssuedCertificate
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.PeerID == peerID {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func (m *mockCAStore) GetIssuedCertificateBySerial(_ context.Context, accountID, serialNumber string) (*IssuedCertificate, error) {
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.SerialNumber == serialNumber {
			return c, nil
		}
	}
	return nil, fmt.Errorf("issued cert not found")
}

func (m *mockCAStore) RevokeCertificate(_ context.Context, accountID, serialNumber string) error {
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.SerialNumber == serialNumber {
			c.Revoked = true
			return nil
		}
	}
	return fmt.Errorf("issued cert not found")
}

func (m *mockCAStore) GetExpiringCertificates(_ context.Context, accountID string, expiringBefore time.Time) ([]*IssuedCertificate, error) {
	var certs []*IssuedCertificate
	for _, c := range m.issuedCerts {
		if c.AccountID == accountID && c.NotAfter.Before(expiringBefore) && !c.Revoked {
			certs = append(certs, c)
		}
	}
	return certs, nil
}

func (m *mockCAStore) CreateCertIssuanceLog(_ context.Context, entry *CertIssuanceLog) error {
	m.issuanceLogs = append(m.issuanceLogs, entry)
	return nil
}

func (m *mockCAStore) CountCertIssuancesInWindow(_ context.Context, accountID, peerID string, since time.Time) (int64, error) {
	var count int64
	for _, l := range m.issuanceLogs {
		if l.AccountID == accountID && l.PeerID == peerID && !l.IssuedAt.Before(since) {
			count++
		}
	}
	return count, nil
}

func createTestCSR(t *testing.T, fqdn string, wildcard bool) *x509.CertificateRequest {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dnsNames := []string{fqdn}
	if wildcard {
		dnsNames = append(dnsNames, "*."+fqdn)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: fqdn},
		DNSNames: dnsNames,
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	return csr
}

func setupTestManager(t *testing.T) (*Manager, *mockCAStore) {
	t.Helper()

	store := newMockCAStore()
	mgr := NewManager(store)
	mgr.RegisterSigner(NewACMEPersistSigner())

	return mgr, store
}

func TestManager_InitForAccount(t *testing.T) {
	mgr, store := setupTestManager(t)

	caCert, err := mgr.InitForAccount(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)
	require.NotNil(t, caCert)

	assert.Equal(t, "account1", caCert.AccountID)
	assert.True(t, caCert.IsActive)
	assert.NotEmpty(t, caCert.Fingerprint)
	assert.NotEmpty(t, caCert.CertificatePEM)
	assert.NotEmpty(t, caCert.PrivateKeyPEM)
	assert.Len(t, store.caCerts, 1)
}

func TestManager_SignCertificate(t *testing.T) {
	mgr, store := setupTestManager(t)

	_, err := mgr.InitForAccount(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)

	csr := createTestCSR(t, "peer1.netbird.example", false)

	result, issued, err := mgr.SignCertificate(
		context.Background(), "account1", "peer1", csr,
		SigningTypeInternal, false, TriggerManual,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, issued)

	assert.NotEmpty(t, result.CertPEM)
	assert.NotEmpty(t, result.ChainPEM)
	assert.Equal(t, "account1", issued.AccountID)
	assert.Equal(t, "peer1", issued.PeerID)
	assert.Equal(t, SigningTypeInternal, issued.SigningType)
	assert.False(t, issued.HasWildcard)
	assert.Contains(t, issued.DNSNames, "peer1.netbird.example")

	assert.Len(t, store.issuedCerts, 1)
	assert.Len(t, store.issuanceLogs, 1)
	assert.Equal(t, TriggerManual, store.issuanceLogs[0].Trigger)
}

func TestManager_SignCertificate_Wildcard(t *testing.T) {
	mgr, _ := setupTestManager(t)

	_, err := mgr.InitForAccount(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)

	csr := createTestCSR(t, "peer1.netbird.example", true)

	result, issued, err := mgr.SignCertificate(
		context.Background(), "account1", "peer1", csr,
		SigningTypeInternal, true, TriggerManual,
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, issued.HasWildcard)
	assert.Contains(t, issued.DNSNames, "*.peer1.netbird.example")
}

func TestManager_SignCertificate_NoActiveCA(t *testing.T) {
	mgr, _ := setupTestManager(t)

	csr := createTestCSR(t, "peer1.netbird.example", false)

	_, _, err := mgr.SignCertificate(
		context.Background(), "account1", "peer1", csr,
		SigningTypeInternal, false, TriggerManual,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active CA")
}

func TestManager_SignCertificate_ACMEStub(t *testing.T) {
	mgr, _ := setupTestManager(t)

	csr := createTestCSR(t, "peer1.netbird.example", false)

	_, _, err := mgr.SignCertificate(
		context.Background(), "account1", "peer1", csr,
		SigningTypeACME, false, TriggerManual,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet available")
}

func TestManager_CheckRateLimit(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		logCount    int
		limit       int
		expectError bool
	}{
		{
			name:        "under limit",
			trigger:     TriggerManual,
			logCount:    5,
			limit:       10,
			expectError: false,
		},
		{
			name:        "at limit",
			trigger:     TriggerManual,
			logCount:    10,
			limit:       10,
			expectError: true,
		},
		{
			name:        "over limit",
			trigger:     TriggerManual,
			logCount:    15,
			limit:       10,
			expectError: true,
		},
		{
			name:        "domain change exempt",
			trigger:     TriggerDomainChange,
			logCount:    100,
			limit:       10,
			expectError: false,
		},
		{
			name:        "renewal at limit",
			trigger:     TriggerRenewal,
			logCount:    10,
			limit:       10,
			expectError: true,
		},
		{
			name:        "zero limit uses default",
			trigger:     TriggerManual,
			logCount:    DefaultRateLimitPerPeer,
			limit:       0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockCAStore()
			mgr := NewManager(store)

			for i := 0; i < tt.logCount; i++ {
				store.issuanceLogs = append(store.issuanceLogs, &CertIssuanceLog{
					AccountID: "account1",
					PeerID:    "peer1",
					IssuedAt:  time.Now().UTC(),
					Trigger:   TriggerManual,
				})
			}

			err := mgr.CheckRateLimit(context.Background(), "account1", "peer1", tt.trigger, tt.limit)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "rate limit")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManager_RotateCA(t *testing.T) {
	mgr, store := setupTestManager(t)

	ca1, err := mgr.InitForAccount(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)

	ca2, err := mgr.RotateCA(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)

	assert.NotEqual(t, ca1.ID, ca2.ID)
	assert.NotEqual(t, ca1.Fingerprint, ca2.Fingerprint)
	assert.Len(t, store.caCerts, 2)

	// Both should be active
	active, err := mgr.GetActiveCACertificates(context.Background(), "account1")
	require.NoError(t, err)
	assert.Len(t, active, 2)
}

func TestManager_DeactivateCA(t *testing.T) {
	mgr, _ := setupTestManager(t)

	caCert, err := mgr.InitForAccount(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)

	err = mgr.DeactivateCA(context.Background(), "account1", caCert.ID)
	require.NoError(t, err)

	active, err := mgr.GetActiveCACertificates(context.Background(), "account1")
	require.NoError(t, err)
	assert.Len(t, active, 0)
}

func TestManager_RevokeCertificate(t *testing.T) {
	mgr, store := setupTestManager(t)

	_, err := mgr.InitForAccount(context.Background(), "account1", "netbird.example", CAOptions{})
	require.NoError(t, err)

	csr := createTestCSR(t, "peer1.netbird.example", false)

	_, issued, err := mgr.SignCertificate(
		context.Background(), "account1", "peer1", csr,
		SigningTypeInternal, false, TriggerManual,
	)
	require.NoError(t, err)

	err = mgr.RevokeCertificate(context.Background(), "account1", issued.SerialNumber)
	require.NoError(t, err)

	assert.True(t, store.issuedCerts[0].Revoked)
}

func TestACMEPersistSigner_ReturnsError(t *testing.T) {
	signer := NewACMEPersistSigner()
	assert.Equal(t, SigningTypeACME, signer.Type())

	_, err := signer.Sign(context.Background(), nil, "", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet available")
}
