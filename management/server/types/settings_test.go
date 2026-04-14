package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceAuthSettings_Defaults(t *testing.T) {
	s := &DeviceAuthSettings{}
	assert.Equal(t, "", s.Mode, "zero-value Mode should be empty string")
	assert.Equal(t, 0, s.CertValidityDays)
}

func TestDeviceAuthSettings_Copy(t *testing.T) {
	original := &DeviceAuthSettings{
		Mode:                      DeviceAuthModeOptional,
		EnrollmentMode:            DeviceAuthEnrollmentManual,
		CAType:                    DeviceAuthCATypeBuiltin,
		CAConfig:                  `{"key":"value"}`,
		CertValidityDays:          180,
		OCSPEnabled:               true,
		FailOpenOnOCSPUnavailable: false,
	}

	copied := original.Copy()
	require.NotNil(t, copied)

	assert.Equal(t, original.Mode, copied.Mode)
	assert.Equal(t, original.EnrollmentMode, copied.EnrollmentMode)
	assert.Equal(t, original.CAType, copied.CAType)
	assert.Equal(t, original.CAConfig, copied.CAConfig)
	assert.Equal(t, original.CertValidityDays, copied.CertValidityDays)
	assert.Equal(t, original.OCSPEnabled, copied.OCSPEnabled)
	assert.Equal(t, original.FailOpenOnOCSPUnavailable, copied.FailOpenOnOCSPUnavailable)

	// Ensure it is a deep copy: mutating original must not affect copy.
	original.Mode = DeviceAuthModeCertOnly
	assert.Equal(t, DeviceAuthModeOptional, copied.Mode, "copy must not be affected by mutation of original")
}

func TestSettings_CopyPreservesDeviceAuth(t *testing.T) {
	da := &DeviceAuthSettings{
		Mode:             DeviceAuthModeCertAndSSO,
		CertValidityDays: 365,
		OCSPEnabled:      true,
	}
	s := &Settings{
		PeerLoginExpirationEnabled: true,
		DeviceAuth:                 da,
	}

	copied := s.Copy()
	require.NotNil(t, copied.DeviceAuth)
	assert.Equal(t, da.Mode, copied.DeviceAuth.Mode)
	assert.Equal(t, da.CertValidityDays, copied.DeviceAuth.CertValidityDays)
	assert.Equal(t, da.OCSPEnabled, copied.DeviceAuth.OCSPEnabled)
}

func TestSettings_CopyNilDeviceAuth(t *testing.T) {
	s := &Settings{
		PeerLoginExpirationEnabled: true,
		DeviceAuth:                 nil,
	}
	copied := s.Copy()
	assert.Nil(t, copied.DeviceAuth, "nil DeviceAuth must remain nil after copy")
}

func TestDeviceAuthModeConstants(t *testing.T) {
	assert.Equal(t, "disabled", DeviceAuthModeDisabled)
	assert.Equal(t, "optional", DeviceAuthModeOptional)
	assert.Equal(t, "cert-only", DeviceAuthModeCertOnly)
	assert.Equal(t, "cert-and-sso", DeviceAuthModeCertAndSSO)
}

func TestDeviceAuthEnrollmentModeConstants(t *testing.T) {
	assert.Equal(t, "manual", DeviceAuthEnrollmentManual)
	assert.Equal(t, "attestation", DeviceAuthEnrollmentAttestation)
	assert.Equal(t, "both", DeviceAuthEnrollmentBoth)
}

func TestDeviceAuthCATypeConstants(t *testing.T) {
	assert.Equal(t, "builtin", DeviceAuthCATypeBuiltin)
	assert.Equal(t, "vault", DeviceAuthCATypeVault)
	assert.Equal(t, "smallstep", DeviceAuthCATypeSmallstep)
	assert.Equal(t, "scep", DeviceAuthCATypeSCEP)
}
