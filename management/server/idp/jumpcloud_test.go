package idp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

func TestNewJumpCloudManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          JumpCloudClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := JumpCloudClientConfig{
		APIToken: "test123",
	}

	testCase1 := test{
		name:                 "Good Configuration",
		inputConfig:          defaultTestConfig,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	testCase2Config := defaultTestConfig
	testCase2Config.APIToken = ""

	testCase2 := test{
		name:                 "Missing APIToken Configuration",
		inputConfig:          testCase2Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	for _, testCase := range []test{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewJumpCloudManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}
