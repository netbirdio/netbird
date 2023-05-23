package idp

import (
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewAuthentikManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          AuthentikClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := AuthentikClientConfig{
		ClientID:      "client_id",
		Username:      "username",
		Password:      "password",
		TokenEndpoint: "https://localhost:8080/application/o/token/",
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
	testCase3Config.Username = ""

	testCase3 := test{
		name:                 "Missing Username Configuration",
		inputConfig:          testCase3Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase4Config := defaultTestConfig
	testCase4Config.Password = ""

	testCase4 := test{
		name:                 "Missing Password Configuration",
		inputConfig:          testCase4Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	//testCase5Config := defaultTestConfig
	//testCase5Config.GrantType = ""
	//
	//testCase5 := test{
	//	name:                 "Missing GrantType Configuration",
	//	inputConfig:          testCase5Config,
	//	assertErrFunc:        require.Error,
	//	assertErrFuncMessage: "should return error when field empty",
	//}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4} {
		t.Run(testCase.name, func(t *testing.T) {
			oidcConfig := OIDCConfig{TokenEndpoint: "https://localhost:8080/application/o/token/"}

			_, err := NewAuthentikManager(oidcConfig, testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}
