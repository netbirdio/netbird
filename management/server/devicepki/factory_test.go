package devicepki_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestNewCA_NilSettings_ReturnsBuiltin(t *testing.T) {
	ctx := context.Background()
	ca, err := devicepki.NewCA(ctx, nil, "acct-nil", nil, "")
	require.NoError(t, err)
	assert.NotNil(t, ca)
	assert.NotNil(t, ca.CACert(ctx))
}

func TestNewCA_EmptyCAType_ReturnsBuiltin(t *testing.T) {
	ctx := context.Background()
	settings := &types.DeviceAuthSettings{CAType: ""}
	ca, err := devicepki.NewCA(ctx, settings, "acct-empty", nil, "")
	require.NoError(t, err)
	assert.NotNil(t, ca.CACert(ctx))
}

func TestNewCA_BuiltinCAType_ReturnsBuiltin(t *testing.T) {
	ctx := context.Background()
	settings := &types.DeviceAuthSettings{CAType: types.DeviceAuthCATypeBuiltin}
	ca, err := devicepki.NewCA(ctx, settings, "acct-builtin", nil, "")
	require.NoError(t, err)
	assert.NotNil(t, ca.CACert(ctx))
}

func TestNewCA_UnknownCAType_ReturnsError(t *testing.T) {
	settings := &types.DeviceAuthSettings{CAType: "nonexistent"}
	_, err := devicepki.NewCA(context.Background(), settings, "acct-unknown", nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown CAType")
}

func TestNewCA_VaultCAType_MissingConfig_ReturnsError(t *testing.T) {
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeVault,
		CAConfig: "",
	}
	_, err := devicepki.NewCA(context.Background(), settings, "acct-vault", nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_config is empty")
}

func TestNewCA_VaultCAType_InvalidJSON_ReturnsError(t *testing.T) {
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeVault,
		CAConfig: "not-json",
	}
	_, err := devicepki.NewCA(context.Background(), settings, "acct-vault", nil, "")
	require.Error(t, err)
}

func TestNewCA_VaultCAType_ValidConfig_ReturnsVaultCA(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"address": "https://vault.example.com:8200",
		"token":   "test-token",
		"mount":   "pki",
		"role":    "netbird-device",
	})
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeVault,
		CAConfig: string(cfg),
	}
	ca, err := devicepki.NewCA(context.Background(), settings, "acct-vault", nil, "")
	require.NoError(t, err)
	assert.NotNil(t, ca)
}

func TestNewCA_SmallstepCAType_MissingConfig_ReturnsError(t *testing.T) {
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeSmallstep,
		CAConfig: "",
	}
	_, err := devicepki.NewCA(context.Background(), settings, "acct-step", nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_config is empty")
}

func TestNewCA_SmallstepCAType_ValidConfig_ReturnsSmallstepCA(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"url":               "https://ca.example.com:9000",
		"provisioner_token": "eyJhbGciOiJFUzI1NiJ9.test",
	})
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeSmallstep,
		CAConfig: string(cfg),
	}
	ca, err := devicepki.NewCA(context.Background(), settings, "acct-step", nil, "")
	require.NoError(t, err)
	assert.NotNil(t, ca)
}

func TestNewCA_SCEPCAType_MissingConfig_ReturnsError(t *testing.T) {
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeSCEP,
		CAConfig: "",
	}
	_, err := devicepki.NewCA(context.Background(), settings, "acct-scep", nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_config is empty")
}

func TestNewCA_SCEPCAType_ValidConfig_ReturnsSCEPCA(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"url":       "http://scep.example.com/scep",
		"challenge": "password123",
	})
	settings := &types.DeviceAuthSettings{
		CAType:   types.DeviceAuthCATypeSCEP,
		CAConfig: string(cfg),
	}
	ca, err := devicepki.NewCA(context.Background(), settings, "acct-scep", nil, "")
	require.NoError(t, err)
	assert.NotNil(t, ca)
}

// TestNewCA_InterfaceCompliance verifies all returned CAs satisfy the CA interface.
func TestNewCA_VaultCA_InterfaceCompliance(t *testing.T) {
	var _ devicepki.CA = (*devicepki.VaultCA)(nil)
}

func TestNewCA_SmallstepCA_InterfaceCompliance(t *testing.T) {
	var _ devicepki.CA = (*devicepki.SmallstepCA)(nil)
}

func TestNewCA_SCEPCA_InterfaceCompliance(t *testing.T) {
	var _ devicepki.CA = (*devicepki.SCEPCA)(nil)
}
