package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/server/config"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestServer_GetDeviceAuthorizationFlow(t *testing.T) {
	testingServerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Errorf("unable to generate server wg key for testing GetDeviceAuthorizationFlow, error: %v", err)
	}

	testingClientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Errorf("unable to generate client wg key for testing GetDeviceAuthorizationFlow, error: %v", err)
	}

	testCases := []struct {
		name                   string
		inputFlow              *config.DeviceAuthorizationFlow
		expectedFlow           *mgmtProto.DeviceAuthorizationFlow
		expectedErrFunc        require.ErrorAssertionFunc
		expectedErrMSG         string
		expectedComparisonFunc require.ComparisonAssertionFunc
		expectedComparisonMSG  string
	}{
		{
			name:            "Testing No Device Flow Config",
			inputFlow:       nil,
			expectedErrFunc: require.Error,
			expectedErrMSG:  "should return error",
		},
		{
			name: "Testing Invalid Device Flow Provider Config",
			inputFlow: &config.DeviceAuthorizationFlow{
				Provider: "NoNe",
				ProviderConfig: config.ProviderConfig{
					ClientID: "test",
				},
			},
			expectedErrFunc: require.Error,
			expectedErrMSG:  "should return error",
		},
		{
			name: "Testing Full Device Flow Config",
			inputFlow: &config.DeviceAuthorizationFlow{
				Provider: "hosted",
				ProviderConfig: config.ProviderConfig{
					ClientID: "test",
				},
			},
			expectedFlow: &mgmtProto.DeviceAuthorizationFlow{
				Provider: 0,
				ProviderConfig: &mgmtProto.ProviderConfig{
					ClientID: "test",
				},
			},
			expectedErrFunc:        require.NoError,
			expectedErrMSG:         "should not return error",
			expectedComparisonFunc: require.Equal,
			expectedComparisonMSG:  "should match",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mgmtServer := &Server{
				secretsManager: &TimeBasedAuthSecretsManager{wgKey: testingServerKey},
				config: &config.Config{
					DeviceAuthorizationFlow: testCase.inputFlow,
				},
			}

			message := &mgmtProto.DeviceAuthorizationFlowRequest{}
			key, err := mgmtServer.secretsManager.GetWGKey()
			require.NoError(t, err, "should be able to get server key")

			encryptedMSG, err := encryption.EncryptMessage(testingClientKey.PublicKey(), key, message)
			require.NoError(t, err, "should be able to encrypt message")

			resp, err := mgmtServer.GetDeviceAuthorizationFlow(
				context.TODO(),
				&mgmtProto.EncryptedMessage{
					WgPubKey: testingClientKey.PublicKey().String(),
					Body:     encryptedMSG,
				},
			)
			testCase.expectedErrFunc(t, err, testCase.expectedErrMSG)
			if testCase.expectedComparisonFunc != nil {
				flowInfoResp := &mgmtProto.DeviceAuthorizationFlow{}

				err = encryption.DecryptMessage(key.PublicKey(), testingClientKey, resp.Body, flowInfoResp)
				require.NoError(t, err, "should be able to decrypt")

				testCase.expectedComparisonFunc(t, testCase.expectedFlow.Provider, flowInfoResp.Provider, testCase.expectedComparisonMSG)
				testCase.expectedComparisonFunc(t, testCase.expectedFlow.ProviderConfig.ClientID, flowInfoResp.ProviderConfig.ClientID, testCase.expectedComparisonMSG)
			}
		})
	}
}
