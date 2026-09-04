package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentityProvider_Validate(t *testing.T) {
	tests := []struct {
		name        string
		idp         *IdentityProvider
		expectedErr error
	}{
		{
			name: "valid OIDC provider",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   "https://example.com",
				ClientID: "client-id",
			},
			expectedErr: nil,
		},
		{
			name: "valid OIDC provider with path",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   "https://example.com/oauth2/issuer",
				ClientID: "client-id",
			},
			expectedErr: nil,
		},
		{
			name: "missing name",
			idp: &IdentityProvider{
				Type:     IdentityProviderTypeOIDC,
				Issuer:   "https://example.com",
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderNameRequired,
		},
		{
			name: "missing type",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Issuer:   "https://example.com",
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderTypeRequired,
		},
		{
			name: "invalid type",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     "invalid",
				Issuer:   "https://example.com",
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderTypeUnsupported,
		},
		{
			name: "missing issuer for OIDC",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     IdentityProviderTypeOIDC,
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderIssuerRequired,
		},
		{
			name: "invalid issuer URL - no scheme",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   "example.com",
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderIssuerInvalid,
		},
		{
			name: "invalid issuer URL - no host",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   "https://",
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderIssuerInvalid,
		},
		{
			name: "invalid issuer URL - just path",
			idp: &IdentityProvider{
				Name:     "Test Provider",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   "/oauth2/issuer",
				ClientID: "client-id",
			},
			expectedErr: ErrIdentityProviderIssuerInvalid,
		},
		{
			name: "missing client ID",
			idp: &IdentityProvider{
				Name:   "Test Provider",
				Type:   IdentityProviderTypeOIDC,
				Issuer: "https://example.com",
			},
			expectedErr: ErrIdentityProviderClientIDRequired,
		},
		{
			name: "Google provider without issuer is valid",
			idp: &IdentityProvider{
				Name:     "Google SSO",
				Type:     IdentityProviderTypeGoogle,
				ClientID: "client-id",
			},
			expectedErr: nil,
		},
		{
			name: "Microsoft provider without issuer is valid",
			idp: &IdentityProvider{
				Name:     "Microsoft SSO",
				Type:     IdentityProviderTypeMicrosoft,
				ClientID: "client-id",
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.idp.Validate()
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestIdentityProvider_ValidateRejectsNonOriginIssuers(t *testing.T) {
	issuers := []string{
		"http://idp.example.com/realms/nb?foo=bar",
		"http://idp.example.com/realms/nb#section",
		"http://user:pass@idp.example.com",
		"ftp://idp.example.com",
		"ldap://idp.example.com",
	}

	for _, issuer := range issuers {
		t.Run(issuer, func(t *testing.T) {
			idp := &IdentityProvider{
				Name:     "test",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   issuer,
				ClientID: "client-id",
			}
			assert.ErrorIs(t, idp.Validate(), ErrIdentityProviderIssuerInvalid)
		})
	}
}

func TestIdentityProvider_ValidateAcceptsOriginAndPath(t *testing.T) {
	for _, issuer := range []string{"https://idp.example.com", "https://idp.example.com/realms/nb", "http://127.0.0.1:5556/dex"} {
		t.Run(issuer, func(t *testing.T) {
			idp := &IdentityProvider{
				Name:     "test",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   issuer,
				ClientID: "client-id",
			}
			assert.NoError(t, idp.Validate())
		})
	}
}

func TestIdentityProviderValidateRejectsBareDelimiters(t *testing.T) {
	for _, issuer := range []string{"https://idp.example.com/realms/nb?", "https://idp.example.com/realms/nb#"} {
		t.Run(issuer, func(t *testing.T) {
			idp := &IdentityProvider{
				Name:     "test",
				Type:     IdentityProviderTypeOIDC,
				Issuer:   issuer,
				ClientID: "client-id",
			}
			assert.ErrorIs(t, idp.Validate(), ErrIdentityProviderIssuerInvalid)
		})
	}
}
