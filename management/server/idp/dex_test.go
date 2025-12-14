package idp

import (
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
	err = manager.UpdateUserAppMetadata(nil, "test-user-id", AppMetadata{
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
	err = manager.InviteUserByID(nil, "test-user-id")
	require.Error(t, err, "InviteUserByID should return error")
	require.Contains(t, err.Error(), "not implemented", "error should mention not implemented")
}
