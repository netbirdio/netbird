package idp

import (
	"testing"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/stretchr/testify/require"
)

func TestNewKeycloakManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          KeycloakClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := KeycloakClientConfig{
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		AdminEndpoint: "https://localhost:8080/auth/admin/realms/test123",
		TokenEndpoint: "https://localhost:8080/auth/realms/test123/protocol/openid-connect/token",
		GrantType:     "client_credentials",
	}

	testCase1 := test{
		name:                 "Good Configuration",
		inputConfig:          defaultTestConfig,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	testCase2Config := defaultTestConfig
	testCase2Config.ClientID = ""

	testCase2 := test{
		name:                 "Missing ClientID Configuration",
		inputConfig:          testCase2Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase3Config := defaultTestConfig
	testCase3Config.AdminEndpoint = "localhost:8080/auth/admin/realms/test123"

	testCase3 := test{
		name:                 "Wrong AdminEndpoint Format",
		inputConfig:          testCase3Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when wrong admin endpoint Format",
	}

	testCase4Config := defaultTestConfig
	testCase4Config.TokenEndpoint = "localhost:8080/auth/realms/test123/protocol/openid-connect/token"

	testCase4 := test{
		name:                 "Wrong TokenEndpoint Format",
		inputConfig:          testCase4Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when wrong token endpoint Format",
	}

	testCase5Config := defaultTestConfig
	testCase5Config.GrantType = "authorization_code"

	testCase5 := test{
		name:                 "Wrong GrantType",
		inputConfig:          testCase5Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when wrong grant type",
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewKeycloakManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}
