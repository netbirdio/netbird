package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func newEnrollmentTestStore(t *testing.T) Store {
	t.Helper()
	s, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)
	return s
}

func TestStore_EnrollmentRequest_Roundtrip(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	req := types.NewEnrollmentRequest("acct1", "peer1", "wg-key-abc", "-----BEGIN CERTIFICATE REQUEST-----", `{"os":"linux"}`)
	require.NoError(t, s.SaveEnrollmentRequest(ctx, LockingStrengthNone, req))

	got, err := s.GetEnrollmentRequest(ctx, LockingStrengthNone, "acct1", req.ID)
	require.NoError(t, err)
	assert.Equal(t, req.ID, got.ID)
	assert.Equal(t, req.WGPublicKey, got.WGPublicKey)
	assert.Equal(t, types.EnrollmentStatusPending, got.Status)
}

func TestStore_EnrollmentRequest_GetByWGKey(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	req := types.NewEnrollmentRequest("acct1", "peer1", "wg-key-xyz", "---CSR---", "{}")
	require.NoError(t, s.SaveEnrollmentRequest(ctx, LockingStrengthNone, req))

	got, err := s.GetEnrollmentRequestByWGKey(ctx, LockingStrengthNone, "acct1", "wg-key-xyz")
	require.NoError(t, err)
	assert.Equal(t, req.ID, got.ID)
}

func TestStore_EnrollmentRequest_ListByAccount(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	for i := 0; i < 3; i++ {
		req := types.NewEnrollmentRequest("acct2", "peer", "key", "csr", "{}")
		require.NoError(t, s.SaveEnrollmentRequest(ctx, LockingStrengthNone, req))
	}
	// Different account — should not appear.
	otherReq := types.NewEnrollmentRequest("acct-other", "peer", "key", "csr", "{}")
	require.NoError(t, s.SaveEnrollmentRequest(ctx, LockingStrengthNone, otherReq))

	list, err := s.ListEnrollmentRequests(ctx, LockingStrengthNone, "acct2")
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

func TestStore_EnrollmentRequest_NotFound(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	_, err := s.GetEnrollmentRequest(ctx, LockingStrengthNone, "acct1", "nonexistent")
	require.Error(t, err)
}

func TestStore_DeviceCertificate_Roundtrip(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	now := time.Now().UTC().Truncate(time.Second)
	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key-abc", "42", "-----BEGIN CERTIFICATE-----\n", now, now.Add(365*24*time.Hour))
	require.NoError(t, s.SaveDeviceCertificate(ctx, LockingStrengthNone, cert))

	got, err := s.GetDeviceCertificateByWGKey(ctx, LockingStrengthNone, "acct1", "wg-key-abc")
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
	assert.Equal(t, cert.Serial, got.Serial)
	assert.False(t, got.Revoked)
}

func TestStore_DeviceCertificate_GetByID(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key", "1", "pem", time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, s.SaveDeviceCertificate(ctx, LockingStrengthNone, cert))

	got, err := s.GetDeviceCertificateByID(ctx, LockingStrengthNone, "acct1", cert.ID)
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
}

func TestStore_DeviceCertificate_Revoke(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	cert := types.NewDeviceCertificate("acct1", "peer1", "wg-key", "99", "pem", time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, s.SaveDeviceCertificate(ctx, LockingStrengthNone, cert))

	revokedAt := time.Now().UTC()
	cert.Revoked = true
	cert.RevokedAt = &revokedAt
	require.NoError(t, s.SaveDeviceCertificate(ctx, LockingStrengthNone, cert))

	got, err := s.GetDeviceCertificateByWGKey(ctx, LockingStrengthNone, "acct1", "wg-key")
	require.NoError(t, err)
	assert.True(t, got.Revoked)
	assert.NotNil(t, got.RevokedAt)
}

func TestStore_DeviceCertificate_ListByAccount(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	for i := 0; i < 2; i++ {
		cert := types.NewDeviceCertificate("acct3", "peer", "key", "1", "pem", time.Now(), time.Now().Add(time.Hour))
		require.NoError(t, s.SaveDeviceCertificate(ctx, LockingStrengthNone, cert))
	}

	list, err := s.ListDeviceCertificates(ctx, LockingStrengthNone, "acct3")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestStore_TrustedCA_Roundtrip(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	ca := types.NewTrustedCA("acct1", "My Root CA", "-----BEGIN CERTIFICATE-----\n")
	require.NoError(t, s.SaveTrustedCA(ctx, LockingStrengthNone, ca))

	got, err := s.GetTrustedCAByID(ctx, LockingStrengthNone, "acct1", ca.ID)
	require.NoError(t, err)
	assert.Equal(t, ca.Name, got.Name)
	assert.Equal(t, ca.PEM, got.PEM)
}

func TestStore_TrustedCA_List(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	for i := 0; i < 3; i++ {
		ca := types.NewTrustedCA("acct4", "CA", "pem")
		require.NoError(t, s.SaveTrustedCA(ctx, LockingStrengthNone, ca))
	}

	list, err := s.ListTrustedCAs(ctx, LockingStrengthNone, "acct4")
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

func TestStore_TrustedCA_Delete(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	ca := types.NewTrustedCA("acct1", "CA", "pem")
	require.NoError(t, s.SaveTrustedCA(ctx, LockingStrengthNone, ca))

	require.NoError(t, s.DeleteTrustedCA(ctx, "acct1", ca.ID))

	_, err := s.GetTrustedCAByID(ctx, LockingStrengthNone, "acct1", ca.ID)
	require.Error(t, err)
}

func TestStore_TrustedCA_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	s := newEnrollmentTestStore(t)

	err := s.DeleteTrustedCA(ctx, "acct1", "nonexistent-id")
	require.Error(t, err)
}
