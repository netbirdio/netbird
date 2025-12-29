package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZitadelManager_AddOIDCConnector(t *testing.T) {
	// Create a mock response for the OIDC connector creation
	mockResponse := `{"id": "oidc-123", "details": {"sequence": "1", "creationDate": "2024-01-01T00:00:00Z", "changeDate": "2024-01-01T00:00:00Z", "resourceOwner": "org-1"}}`

	mockClient := &mockHTTPClient{
		code:    http.StatusCreated,
		resBody: mockResponse,
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	config := OIDCConnectorConfig{
		Name:         "Okta",
		Issuer:       "https://okta.example.com",
		ClientID:     "client-123",
		ClientSecret: "secret-456",
		Scopes:       []string{"openid", "profile", "email"},
	}

	connector, err := manager.AddOIDCConnector(context.Background(), config)
	require.NoError(t, err)
	assert.Equal(t, "oidc-123", connector.ID)
	assert.Equal(t, "Okta", connector.Name)
	assert.Equal(t, ConnectorTypeOIDC, connector.Type)
	assert.Equal(t, "https://okta.example.com", connector.Issuer)

	// Verify the request body contains expected fields
	var reqBody map[string]any
	err = json.Unmarshal([]byte(mockClient.reqBody), &reqBody)
	require.NoError(t, err)
	assert.Equal(t, "Okta", reqBody["name"])
	assert.Equal(t, "https://okta.example.com", reqBody["issuer"])
	assert.Equal(t, "client-123", reqBody["clientId"])
}

func TestZitadelManager_AddLDAPConnector(t *testing.T) {
	mockResponse := `{"id": "ldap-456", "details": {"sequence": "1", "creationDate": "2024-01-01T00:00:00Z", "changeDate": "2024-01-01T00:00:00Z", "resourceOwner": "org-1"}}`

	mockClient := &mockHTTPClient{
		code:    http.StatusCreated,
		resBody: mockResponse,
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	config := LDAPConnectorConfig{
		Name:         "Corporate LDAP",
		Servers:      []string{"ldap://ldap.example.com:389"},
		BaseDN:       "dc=example,dc=com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "admin-password",
		Attributes: LDAPAttributes{
			IDAttribute:    "uid",
			EmailAttribute: "mail",
		},
	}

	connector, err := manager.AddLDAPConnector(context.Background(), config)
	require.NoError(t, err)
	assert.Equal(t, "ldap-456", connector.ID)
	assert.Equal(t, "Corporate LDAP", connector.Name)
	assert.Equal(t, ConnectorTypeLDAP, connector.Type)
	assert.Equal(t, []string{"ldap://ldap.example.com:389"}, connector.Servers)
}

func TestZitadelManager_AddSAMLConnector(t *testing.T) {
	mockResponse := `{"id": "saml-789", "details": {"sequence": "1", "creationDate": "2024-01-01T00:00:00Z", "changeDate": "2024-01-01T00:00:00Z", "resourceOwner": "org-1"}}`

	mockClient := &mockHTTPClient{
		code:    http.StatusCreated,
		resBody: mockResponse,
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	config := SAMLConnectorConfig{
		Name:        "Enterprise SAML",
		MetadataURL: "https://idp.example.com/metadata.xml",
	}

	connector, err := manager.AddSAMLConnector(context.Background(), config)
	require.NoError(t, err)
	assert.Equal(t, "saml-789", connector.ID)
	assert.Equal(t, "Enterprise SAML", connector.Name)
	assert.Equal(t, ConnectorTypeSAML, connector.Type)
}

func TestZitadelManager_AddSAMLConnector_RequiresMetadata(t *testing.T) {
	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         &mockHTTPClient{},
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	config := SAMLConnectorConfig{
		Name: "Invalid SAML",
		// Neither MetadataXML nor MetadataURL provided
	}

	_, err := manager.AddSAMLConnector(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadataXml or metadataUrl must be provided")
}

func TestZitadelManager_ListConnectors(t *testing.T) {
	mockResponse := `{
		"result": [
			{
				"id": "oidc-1",
				"name": "Google",
				"state": "IDP_STATE_ACTIVE",
				"type": "IDP_TYPE_OIDC",
				"oidc": {"issuer": "https://accounts.google.com", "clientId": "google-client"}
			},
			{
				"id": "ldap-1",
				"name": "AD",
				"state": "IDP_STATE_INACTIVE",
				"type": "IDP_TYPE_LDAP",
				"ldap": {"servers": ["ldap://ad.example.com:389"], "baseDn": "dc=example,dc=com"}
			}
		]
	}`

	mockClient := &mockHTTPClient{
		code:    http.StatusOK,
		resBody: mockResponse,
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	connectors, err := manager.ListConnectors(context.Background())
	require.NoError(t, err)
	require.Len(t, connectors, 2)

	assert.Equal(t, "oidc-1", connectors[0].ID)
	assert.Equal(t, "Google", connectors[0].Name)
	assert.Equal(t, "active", connectors[0].State)
	assert.Equal(t, ConnectorTypeOIDC, connectors[0].Type)
	assert.Equal(t, "https://accounts.google.com", connectors[0].Issuer)

	assert.Equal(t, "ldap-1", connectors[1].ID)
	assert.Equal(t, "AD", connectors[1].Name)
	assert.Equal(t, "inactive", connectors[1].State)
	assert.Equal(t, ConnectorTypeLDAP, connectors[1].Type)
	assert.Equal(t, []string{"ldap://ad.example.com:389"}, connectors[1].Servers)
}

func TestZitadelManager_GetConnector(t *testing.T) {
	mockResponse := `{
		"idp": {
			"id": "oidc-123",
			"name": "Okta",
			"state": "IDP_STATE_ACTIVE",
			"type": "IDP_TYPE_OIDC",
			"oidc": {"issuer": "https://okta.example.com", "clientId": "client-123"}
		}
	}`

	mockClient := &mockHTTPClient{
		code:    http.StatusOK,
		resBody: mockResponse,
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	connector, err := manager.GetConnector(context.Background(), "oidc-123")
	require.NoError(t, err)
	assert.Equal(t, "oidc-123", connector.ID)
	assert.Equal(t, "Okta", connector.Name)
	assert.Equal(t, ConnectorTypeOIDC, connector.Type)
	assert.Equal(t, "https://okta.example.com", connector.Issuer)
}

func TestZitadelManager_DeleteConnector(t *testing.T) {
	mockClient := &mockHTTPClient{
		code:    http.StatusOK,
		resBody: "{}",
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	err := manager.DeleteConnector(context.Background(), "oidc-123")
	require.NoError(t, err)
}

func TestZitadelManager_ActivateConnector(t *testing.T) {
	mockClient := &mockHTTPClient{
		code:    http.StatusOK,
		resBody: "{}",
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	err := manager.ActivateConnector(context.Background(), "oidc-123")
	require.NoError(t, err)

	// Verify the request body
	var reqBody map[string]string
	err = json.Unmarshal([]byte(mockClient.reqBody), &reqBody)
	require.NoError(t, err)
	assert.Equal(t, "oidc-123", reqBody["idpId"])
}

func TestZitadelManager_DeactivateConnector(t *testing.T) {
	mockClient := &mockHTTPClient{
		code:    http.StatusOK,
		resBody: "{}",
	}

	manager := &ZitadelManager{
		managementEndpoint: "https://zitadel.example.com/management/v1",
		httpClient:         mockClient,
		credentials:        &mockCredentials{token: "test-token"},
		helper:             JsonParser{},
	}

	err := manager.DeactivateConnector(context.Background(), "oidc-123")
	require.NoError(t, err)
}

func TestNormalizeState(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"IDP_STATE_ACTIVE", "active"},
		{"IDP_STATE_INACTIVE", "inactive"},
		{"custom", "custom"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, normalizeState(tc.input))
		})
	}
}

func TestNormalizeType(t *testing.T) {
	tests := []struct {
		input    string
		expected ConnectorType
	}{
		{"IDP_TYPE_OIDC", ConnectorTypeOIDC},
		{"IDP_TYPE_OIDC_GENERIC", ConnectorTypeOIDC},
		{"IDP_TYPE_LDAP", ConnectorTypeLDAP},
		{"IDP_TYPE_SAML", ConnectorTypeSAML},
		{"CUSTOM", ConnectorType("CUSTOM")},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, normalizeType(tc.input))
		})
	}
}

// mockCredentials is a mock implementation of ManagerCredentials for testing
type mockCredentials struct {
	token string
}

func (m *mockCredentials) Authenticate(ctx context.Context) (JWTToken, error) {
	return JWTToken{AccessToken: m.token}, nil
}
