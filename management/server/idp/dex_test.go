package idp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

func TestNewDexManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          DexClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := DexClientConfig{
		GRPCAddr: "localhost:5557",
		Issuer:   "https://dex.example.com/dex",
	}

	testCase1 := test{
		name:                 "Good Configuration",
		inputConfig:          defaultTestConfig,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	testCase2Config := defaultTestConfig
	testCase2Config.GRPCAddr = ""

	testCase2 := test{
		name:                 "Missing GRPCAddr Configuration",
		inputConfig:          testCase2Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when GRPCAddr is empty",
	}

	// Test with empty issuer - should still work since issuer is optional for the manager
	testCase3Config := defaultTestConfig
	testCase3Config.Issuer = ""

	testCase3 := test{
		name:                 "Missing Issuer Configuration - OK",
		inputConfig:          testCase3Config,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error when issuer is empty",
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3} {
		t.Run(testCase.name, func(t *testing.T) {
			manager, err := NewDexManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)

			if err == nil {
				require.NotNil(t, manager, "manager should not be nil")
				require.Equal(t, testCase.inputConfig.GRPCAddr, manager.grpcAddr, "grpcAddr should match")
			}
		})
	}
}

func TestDexManagerUpdateUserAppMetadata(t *testing.T) {
	config := DexClientConfig{
		GRPCAddr: "localhost:5557",
		Issuer:   "https://dex.example.com/dex",
	}

	manager, err := NewDexManager(config, &telemetry.MockAppMetrics{})
	require.NoError(t, err, "should create manager without error")

	// UpdateUserAppMetadata should be a no-op for Dex
	err = manager.UpdateUserAppMetadata(context.Background(), "test-user-id", AppMetadata{
		WTAccountID: "test-account",
	})
	require.NoError(t, err, "UpdateUserAppMetadata should not return error")
}

func TestDexManagerInviteUserByID(t *testing.T) {
	config := DexClientConfig{
		GRPCAddr: "localhost:5557",
		Issuer:   "https://dex.example.com/dex",
	}

	manager, err := NewDexManager(config, &telemetry.MockAppMetrics{})
	require.NoError(t, err, "should create manager without error")

	// InviteUserByID should return an error for Dex
	err = manager.InviteUserByID(context.Background(), "test-user-id")
	require.Error(t, err, "InviteUserByID should return error")
	require.Contains(t, err.Error(), "not implemented", "error should mention not implemented")
}

func TestParseDexUserID(t *testing.T) {
	tests := []struct {
		name        string
		compositeID string
		expectedID  string
	}{
		{
			name: "Parse base64-encoded protobuf composite ID",
			// This is a real Dex composite ID: contains user ID "cf5db180-d360-484d-9b78-c5db92146420" and connector "local"
			compositeID: "CiRjZjVkYjE4MC1kMzYwLTQ4NGQtOWI3OC1jNWRiOTIxNDY0MjASBWxvY2Fs",
			expectedID:  "cf5db180-d360-484d-9b78-c5db92146420",
		},
		{
			name:        "Return plain ID unchanged",
			compositeID: "simple-user-id",
			expectedID:  "simple-user-id",
		},
		{
			name:        "Return UUID unchanged",
			compositeID: "cf5db180-d360-484d-9b78-c5db92146420",
			expectedID:  "cf5db180-d360-484d-9b78-c5db92146420",
		},
		{
			name:        "Handle empty string",
			compositeID: "",
			expectedID:  "",
		},
		{
			name:        "Handle invalid base64",
			compositeID: "not-valid-base64!!!",
			expectedID:  "not-valid-base64!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDexUserID(tt.compositeID)
			require.Equal(t, tt.expectedID, result, "parsed user ID should match expected")
		})
	}
}
