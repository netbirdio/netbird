package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/client/common"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestApplySessionExtendFlowPolicy(t *testing.T) {
	tests := []struct {
		name               string
		flow               *proto.PKCEAuthorizationFlow
		sessionExtend      bool
		disablePromptLogin bool
		loginFlag          uint32
	}{
		{
			name: "extend forces prompt=login over a silent flow",
			flow: &proto.PKCEAuthorizationFlow{
				ProviderConfig: &proto.ProviderConfig{
					DisablePromptLogin: true,
					LoginFlag:          uint32(common.LoginFlagMaxAge0),
				},
			},
			sessionExtend:      true,
			disablePromptLogin: false,
			loginFlag:          uint32(common.LoginFlagPromptLogin),
		},
		{
			name: "extend replaces max_age=0 so login_hint is honoured",
			flow: &proto.PKCEAuthorizationFlow{
				ProviderConfig: &proto.ProviderConfig{
					DisablePromptLogin: false,
					LoginFlag:          uint32(common.LoginFlagMaxAge0),
				},
			},
			sessionExtend:      true,
			disablePromptLogin: false,
			loginFlag:          uint32(common.LoginFlagPromptLogin),
		},
		{
			name: "login keeps the configured flow untouched",
			flow: &proto.PKCEAuthorizationFlow{
				ProviderConfig: &proto.ProviderConfig{
					DisablePromptLogin: true,
					LoginFlag:          uint32(common.LoginFlagMaxAge0),
				},
			},
			sessionExtend:      false,
			disablePromptLogin: true,
			loginFlag:          uint32(common.LoginFlagMaxAge0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			applySessionExtendFlowPolicy(tc.flow, tc.sessionExtend)
			cfg := tc.flow.GetProviderConfig()
			assert.Equal(t, tc.disablePromptLogin, cfg.GetDisablePromptLogin())
			assert.Equal(t, tc.loginFlag, cfg.GetLoginFlag())
		})
	}
}

// A provider config is not guaranteed to be present on the response; clearing
// the flag must not panic when the validator returned an empty flow.
func TestApplySessionExtendFlowPolicyWithoutProviderConfig(t *testing.T) {
	assert.NotPanics(t, func() {
		applySessionExtendFlowPolicy(&proto.PKCEAuthorizationFlow{}, true)
		applySessionExtendFlowPolicy(nil, true)
	})
}
