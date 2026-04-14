package grpc

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestValidateCSRPEM_Valid(t *testing.T) {
	csrPEM := buildCSRPEM(t)
	assert.NoError(t, validateCSRPEM(csrPEM))
}

func TestValidateCSRPEM_Empty(t *testing.T) {
	err := validateCSRPEM("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateCSRPEM_InvalidPEM(t *testing.T) {
	err := validateCSRPEM("not-a-pem-block")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode PEM block")
}

func TestValidateCSRPEM_WrongType(t *testing.T) {
	// A CERTIFICATE block is not a CERTIFICATE REQUEST.
	block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}
	err := validateCSRPEM(string(pem.EncodeToMemory(block)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected PEM type")
}

func TestExtractSerialFromSystemInfo_Valid(t *testing.T) {
	systemInfo := `{"SystemSerialNumber":"SN-001234","OS":"macOS"}`
	assert.Equal(t, "SN-001234", extractSerialFromSystemInfo(systemInfo))
}

func TestExtractSerialFromSystemInfo_Empty(t *testing.T) {
	assert.Equal(t, "", extractSerialFromSystemInfo(""))
}

func TestExtractSerialFromSystemInfo_MissingField(t *testing.T) {
	assert.Equal(t, "", extractSerialFromSystemInfo(`{"OS":"Windows"}`))
}

func TestExtractSerialFromSystemInfo_MalformedJSON(t *testing.T) {
	assert.Equal(t, "", extractSerialFromSystemInfo("{not-valid-json"))
}

func TestExtractSerialFromSystemInfo_EmptySerial(t *testing.T) {
	// Field present but empty string.
	assert.Equal(t, "", extractSerialFromSystemInfo(`{"SystemSerialNumber":""}`))
}

func TestExtractSerialFromSystemInfo_SerialWithSpecialChars(t *testing.T) {
	systemInfo := `{"SystemSerialNumber":"C02XG123JGH5","OS":"macOS 14.4"}`
	assert.Equal(t, "C02XG123JGH5", extractSerialFromSystemInfo(systemInfo))
}

// ─── shouldRecheckInventory tests ─────────────────────────────────────────────

func TestShouldRecheckInventory_NilLastCheck(t *testing.T) {
	cert := &types.DeviceCertificate{LastInventoryCheckAt: nil}
	assert.True(t, shouldRecheckInventory(cert, 24), "nil LastInventoryCheckAt → always recheck")
}

func TestShouldRecheckInventory_RecentCheck(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	cert := &types.DeviceCertificate{LastInventoryCheckAt: &recent}
	assert.False(t, shouldRecheckInventory(cert, 24), "1h ago within 24h interval → skip recheck")
}

func TestShouldRecheckInventory_ExpiredCheck(t *testing.T) {
	old := time.Now().Add(-25 * time.Hour)
	cert := &types.DeviceCertificate{LastInventoryCheckAt: &old}
	assert.True(t, shouldRecheckInventory(cert, 24), "25h ago beyond 24h interval → recheck")
}

func TestShouldRecheckInventory_ZeroIntervalAlwaysRechecks(t *testing.T) {
	// intervalHours=0 means "always recheck" — even a very recent check does not skip.
	recent := time.Now().Add(-1 * time.Minute)
	cert := &types.DeviceCertificate{LastInventoryCheckAt: &recent}
	assert.True(t, shouldRecheckInventory(cert, 0), "intervalHours=0 → always recheck regardless of last check time")
}

func TestShouldRecheckInventory_NegativeIntervalDefaultsTo24h(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	cert := &types.DeviceCertificate{LastInventoryCheckAt: &recent}
	assert.False(t, shouldRecheckInventory(cert, -5), "negative interval defaults to 24h; recent check → skip")
}

// ─── performInventoryRecheck tests ────────────────────────────────────────────

// stubInventory is a minimal Inventory implementation for testing.
type stubInventory struct {
	registered bool
	err        error
}

func (s *stubInventory) IsRegistered(_ context.Context, _ string) (bool, error) {
	return s.registered, s.err
}

func TestPerformInventoryRecheck_DeviceRegistered_UpdatesTimestamp(t *testing.T) {
	cert := &types.DeviceCertificate{WGPublicKey: "wg1"}
	inv := &stubInventory{registered: true}

	updatedAt, err := performInventoryRecheck(context.Background(), inv, "serial-01", cert)
	require.NoError(t, err)
	require.NotNil(t, updatedAt, "should return an updated LastInventoryCheckAt timestamp")
	assert.WithinDuration(t, time.Now(), *updatedAt, 5*time.Second)
}

func TestPerformInventoryRecheck_DeviceNotRegistered_ReturnsError(t *testing.T) {
	cert := &types.DeviceCertificate{WGPublicKey: "wg1"}
	inv := &stubInventory{registered: false}

	updatedAt, err := performInventoryRecheck(context.Background(), inv, "serial-01", cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer")
	assert.Nil(t, updatedAt)
}

func TestPerformInventoryRecheck_InventoryError_ReturnsError(t *testing.T) {
	cert := &types.DeviceCertificate{WGPublicKey: "wg1"}
	inv := &stubInventory{err: errors.New("MDM unreachable")}

	updatedAt, err := performInventoryRecheck(context.Background(), inv, "serial-01", cert)
	require.Error(t, err)
	assert.Nil(t, updatedAt)
}

// TestTryAttestationEnrollment_ReturnsUnimplemented verifies that the old single-round
// attestation path is disabled and returns codes.Unimplemented for any non-nil proof.
func TestTryAttestationEnrollment_ReturnsUnimplemented(t *testing.T) {
	s := &Server{}
	// A non-nil AttestationProof triggers the old path.
	ap := &proto.AttestationProof{}
	_, handled, err := s.tryAttestationEnrollment(
		context.Background(),
		wgtypes.Key{},
		"account-id", "peer-id", "wg-pub-key",
		&proto.DeviceEnrollRequest{},
		ap,
	)
	require.True(t, handled, "non-nil proof must always set handled=true")
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status error")
	assert.Equal(t, codes.Unimplemented, st.Code())
}

func TestTryAttestationEnrollment_NilProof_FallsThrough(t *testing.T) {
	s := &Server{}
	resp, handled, err := s.tryAttestationEnrollment(
		context.Background(),
		wgtypes.Key{},
		"account-id", "peer-id", "wg-pub-key",
		&proto.DeviceEnrollRequest{},
		nil, // nil proof → fall through
	)
	require.NoError(t, err)
	assert.False(t, handled, "nil proof must not set handled")
	assert.Nil(t, resp)
}

func TestEnrollmentRequest_IsActive(t *testing.T) {
	tests := []struct {
		status string
		active bool
	}{
		{types.EnrollmentStatusPending, true},
		{types.EnrollmentStatusApproved, true},
		{types.EnrollmentStatusRejected, false},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			req := &types.EnrollmentRequest{Status: tt.status}
			assert.Equal(t, tt.active, req.IsActive())
		})
	}
}
