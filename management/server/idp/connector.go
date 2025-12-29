package idp

import (
	"context"
	"fmt"
)

// ConnectorType represents the type of external identity provider connector
type ConnectorType string

const (
	ConnectorTypeOIDC ConnectorType = "oidc"
	ConnectorTypeLDAP ConnectorType = "ldap"
	ConnectorTypeSAML ConnectorType = "saml"
)

// Connector represents an external identity provider configured in Zitadel
type Connector struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Type    ConnectorType `json:"type"`
	State   string        `json:"state"`
	Issuer  string        `json:"issuer,omitempty"`  // for OIDC
	Servers []string      `json:"servers,omitempty"` // for LDAP
}

// OIDCConnectorConfig contains configuration for adding an OIDC connector
type OIDCConnectorConfig struct {
	Name                  string   `json:"name"`
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"clientId"`
	ClientSecret          string   `json:"clientSecret"`
	Scopes                []string `json:"scopes,omitempty"`
	IsIDTokenMapping      bool     `json:"isIdTokenMapping,omitempty"`
	IsAutoCreation        bool     `json:"isAutoCreation,omitempty"`
	IsAutoUpdate          bool     `json:"isAutoUpdate,omitempty"`
	IsCreationAllowed     bool     `json:"isCreationAllowed,omitempty"`
	IsLinkingAllowed      bool     `json:"isLinkingAllowed,omitempty"`
	IsAutoAccountLinking  bool     `json:"isAutoAccountLinking,omitempty"`
	AccountLinkingEnabled bool     `json:"accountLinkingEnabled,omitempty"`
}

// LDAPConnectorConfig contains configuration for adding an LDAP connector
type LDAPConnectorConfig struct {
	Name             string            `json:"name"`
	Servers          []string          `json:"servers"` // e.g., ["ldap://localhost:389"]
	StartTLS         bool              `json:"startTls,omitempty"`
	BaseDN           string            `json:"baseDn"`
	BindDN           string            `json:"bindDn"`
	BindPassword     string            `json:"bindPassword"`
	UserBase         string            `json:"userBase,omitempty"`         // typically "dn"
	UserObjectClass  []string          `json:"userObjectClass,omitempty"`  // e.g., ["user", "person"]
	UserFilters      []string          `json:"userFilters,omitempty"`      // e.g., ["uid", "email"]
	Timeout          string            `json:"timeout,omitempty"`          // e.g., "10s"
	Attributes       LDAPAttributes    `json:"attributes,omitempty"`
	IsAutoCreation   bool              `json:"isAutoCreation,omitempty"`
	IsAutoUpdate     bool              `json:"isAutoUpdate,omitempty"`
	IsCreationAllowed bool             `json:"isCreationAllowed,omitempty"`
	IsLinkingAllowed  bool             `json:"isLinkingAllowed,omitempty"`
}

// LDAPAttributes maps LDAP attributes to Zitadel user fields
type LDAPAttributes struct {
	IDAttribute          string `json:"idAttribute,omitempty"`
	FirstNameAttribute   string `json:"firstNameAttribute,omitempty"`
	LastNameAttribute    string `json:"lastNameAttribute,omitempty"`
	DisplayNameAttribute string `json:"displayNameAttribute,omitempty"`
	NickNameAttribute    string `json:"nickNameAttribute,omitempty"`
	EmailAttribute       string `json:"emailAttribute,omitempty"`
	EmailVerified        string `json:"emailVerified,omitempty"`
	PhoneAttribute       string `json:"phoneAttribute,omitempty"`
	PhoneVerified        string `json:"phoneVerified,omitempty"`
	AvatarURLAttribute   string `json:"avatarUrlAttribute,omitempty"`
	ProfileAttribute     string `json:"profileAttribute,omitempty"`
}

// SAMLConnectorConfig contains configuration for adding a SAML connector
type SAMLConnectorConfig struct {
	Name                    string `json:"name"`
	MetadataXML             string `json:"metadataXml,omitempty"`
	MetadataURL             string `json:"metadataUrl,omitempty"`
	Binding                 string `json:"binding,omitempty"` // "SAML_BINDING_POST" or "SAML_BINDING_REDIRECT"
	WithSignedRequest       bool   `json:"withSignedRequest,omitempty"`
	NameIDFormat            string `json:"nameIdFormat,omitempty"`
	IsAutoCreation          bool   `json:"isAutoCreation,omitempty"`
	IsAutoUpdate            bool   `json:"isAutoUpdate,omitempty"`
	IsCreationAllowed       bool   `json:"isCreationAllowed,omitempty"`
	IsLinkingAllowed        bool   `json:"isLinkingAllowed,omitempty"`
}

// ConnectorManager defines the interface for managing external IdP connectors
type ConnectorManager interface {
	// AddOIDCConnector adds a Generic OIDC identity provider connector
	AddOIDCConnector(ctx context.Context, config OIDCConnectorConfig) (*Connector, error)
	// AddLDAPConnector adds an LDAP identity provider connector
	AddLDAPConnector(ctx context.Context, config LDAPConnectorConfig) (*Connector, error)
	// AddSAMLConnector adds a SAML identity provider connector
	AddSAMLConnector(ctx context.Context, config SAMLConnectorConfig) (*Connector, error)
	// ListConnectors returns all configured identity provider connectors
	ListConnectors(ctx context.Context) ([]*Connector, error)
	// GetConnector returns a specific connector by ID
	GetConnector(ctx context.Context, connectorID string) (*Connector, error)
	// DeleteConnector removes an identity provider connector
	DeleteConnector(ctx context.Context, connectorID string) error
	// ActivateConnector adds the connector to the login policy
	ActivateConnector(ctx context.Context, connectorID string) error
	// DeactivateConnector removes the connector from the login policy
	DeactivateConnector(ctx context.Context, connectorID string) error
}

// zitadelProviderResponse represents the response from creating a provider
type zitadelProviderResponse struct {
	ID      string `json:"id"`
	Details struct {
		Sequence      string `json:"sequence"`
		CreationDate  string `json:"creationDate"`
		ChangeDate    string `json:"changeDate"`
		ResourceOwner string `json:"resourceOwner"`
	} `json:"details"`
}

// zitadelProviderTemplate represents a provider in the list response
type zitadelProviderTemplate struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"` // IDP_STATE_ACTIVE, IDP_STATE_INACTIVE
	Type  string `json:"type"`  // IDP_TYPE_OIDC, IDP_TYPE_LDAP, IDP_TYPE_SAML, etc.
	Owner string `json:"owner"` // IDP_OWNER_TYPE_ORG, IDP_OWNER_TYPE_SYSTEM
	// Type-specific fields
	OIDC *struct {
		Issuer   string `json:"issuer"`
		ClientID string `json:"clientId"`
	} `json:"oidc,omitempty"`
	LDAP *struct {
		Servers []string `json:"servers"`
		BaseDN  string   `json:"baseDn"`
	} `json:"ldap,omitempty"`
	SAML *struct {
		MetadataURL string `json:"metadataUrl"`
	} `json:"saml,omitempty"`
}

// AddOIDCConnector adds a Generic OIDC identity provider connector to Zitadel
func (zm *ZitadelManager) AddOIDCConnector(ctx context.Context, config OIDCConnectorConfig) (*Connector, error) {
	// Set defaults for creation/linking if not specified
	if !config.IsCreationAllowed && !config.IsLinkingAllowed {
		config.IsCreationAllowed = true
		config.IsLinkingAllowed = true
	}

	payload := map[string]any{
		"name":                 config.Name,
		"issuer":               config.Issuer,
		"clientId":             config.ClientID,
		"clientSecret":         config.ClientSecret,
		"isIdTokenMapping":     config.IsIDTokenMapping,
		"isAutoCreation":       config.IsAutoCreation,
		"isAutoUpdate":         config.IsAutoUpdate,
		"isCreationAllowed":    config.IsCreationAllowed,
		"isLinkingAllowed":     config.IsLinkingAllowed,
	}

	if len(config.Scopes) > 0 {
		payload["scopes"] = config.Scopes
	}

	body, err := zm.helper.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal OIDC connector config: %w", err)
	}

	respBody, err := zm.post(ctx, "idps/generic_oidc", string(body))
	if err != nil {
		return nil, fmt.Errorf("add OIDC connector: %w", err)
	}

	var resp zitadelProviderResponse
	if err := zm.helper.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal OIDC connector response: %w", err)
	}

	return &Connector{
		ID:     resp.ID,
		Name:   config.Name,
		Type:   ConnectorTypeOIDC,
		State:  "active",
		Issuer: config.Issuer,
	}, nil
}

// AddLDAPConnector adds an LDAP identity provider connector to Zitadel
func (zm *ZitadelManager) AddLDAPConnector(ctx context.Context, config LDAPConnectorConfig) (*Connector, error) {
	// Set defaults
	if !config.IsCreationAllowed && !config.IsLinkingAllowed {
		config.IsCreationAllowed = true
		config.IsLinkingAllowed = true
	}
	if config.UserBase == "" {
		config.UserBase = "dn"
	}
	if config.Timeout == "" {
		config.Timeout = "10s"
	}

	payload := map[string]any{
		"name":              config.Name,
		"servers":           config.Servers,
		"startTls":          config.StartTLS,
		"baseDn":            config.BaseDN,
		"bindDn":            config.BindDN,
		"bindPassword":      config.BindPassword,
		"userBase":          config.UserBase,
		"timeout":           config.Timeout,
		"isAutoCreation":    config.IsAutoCreation,
		"isAutoUpdate":      config.IsAutoUpdate,
		"isCreationAllowed": config.IsCreationAllowed,
		"isLinkingAllowed":  config.IsLinkingAllowed,
	}

	if len(config.UserObjectClass) > 0 {
		payload["userObjectClasses"] = config.UserObjectClass
	}
	if len(config.UserFilters) > 0 {
		payload["userFilters"] = config.UserFilters
	}

	// Add attribute mappings if provided
	attrs := make(map[string]string)
	if config.Attributes.IDAttribute != "" {
		attrs["idAttribute"] = config.Attributes.IDAttribute
	}
	if config.Attributes.FirstNameAttribute != "" {
		attrs["firstNameAttribute"] = config.Attributes.FirstNameAttribute
	}
	if config.Attributes.LastNameAttribute != "" {
		attrs["lastNameAttribute"] = config.Attributes.LastNameAttribute
	}
	if config.Attributes.DisplayNameAttribute != "" {
		attrs["displayNameAttribute"] = config.Attributes.DisplayNameAttribute
	}
	if config.Attributes.EmailAttribute != "" {
		attrs["emailAttribute"] = config.Attributes.EmailAttribute
	}
	if len(attrs) > 0 {
		payload["attributes"] = attrs
	}

	body, err := zm.helper.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal LDAP connector config: %w", err)
	}

	respBody, err := zm.post(ctx, "idps/ldap", string(body))
	if err != nil {
		return nil, fmt.Errorf("add LDAP connector: %w", err)
	}

	var resp zitadelProviderResponse
	if err := zm.helper.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal LDAP connector response: %w", err)
	}

	return &Connector{
		ID:      resp.ID,
		Name:    config.Name,
		Type:    ConnectorTypeLDAP,
		State:   "active",
		Servers: config.Servers,
	}, nil
}

// AddSAMLConnector adds a SAML identity provider connector to Zitadel
func (zm *ZitadelManager) AddSAMLConnector(ctx context.Context, config SAMLConnectorConfig) (*Connector, error) {
	// Set defaults
	if !config.IsCreationAllowed && !config.IsLinkingAllowed {
		config.IsCreationAllowed = true
		config.IsLinkingAllowed = true
	}

	payload := map[string]any{
		"name":              config.Name,
		"isAutoCreation":    config.IsAutoCreation,
		"isAutoUpdate":      config.IsAutoUpdate,
		"isCreationAllowed": config.IsCreationAllowed,
		"isLinkingAllowed":  config.IsLinkingAllowed,
	}

	if config.MetadataXML != "" {
		payload["metadataXml"] = config.MetadataXML
	} else if config.MetadataURL != "" {
		payload["metadataUrl"] = config.MetadataURL
	} else {
		return nil, fmt.Errorf("either metadataXml or metadataUrl must be provided")
	}

	if config.Binding != "" {
		payload["binding"] = config.Binding
	}
	if config.WithSignedRequest {
		payload["withSignedRequest"] = config.WithSignedRequest
	}
	if config.NameIDFormat != "" {
		payload["nameIdFormat"] = config.NameIDFormat
	}

	body, err := zm.helper.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal SAML connector config: %w", err)
	}

	respBody, err := zm.post(ctx, "idps/saml", string(body))
	if err != nil {
		return nil, fmt.Errorf("add SAML connector: %w", err)
	}

	var resp zitadelProviderResponse
	if err := zm.helper.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal SAML connector response: %w", err)
	}

	return &Connector{
		ID:    resp.ID,
		Name:  config.Name,
		Type:  ConnectorTypeSAML,
		State: "active",
	}, nil
}

// ListConnectors returns all configured identity provider connectors
func (zm *ZitadelManager) ListConnectors(ctx context.Context) ([]*Connector, error) {
	// Use the search endpoint to list all providers
	respBody, err := zm.post(ctx, "idps/_search", "{}")
	if err != nil {
		return nil, fmt.Errorf("list connectors: %w", err)
	}

	var resp struct {
		Result []zitadelProviderTemplate `json:"result"`
	}
	if err := zm.helper.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal connectors response: %w", err)
	}

	connectors := make([]*Connector, 0, len(resp.Result))
	for _, p := range resp.Result {
		connector := &Connector{
			ID:    p.ID,
			Name:  p.Name,
			State: normalizeState(p.State),
			Type:  normalizeType(p.Type),
		}

		// Add type-specific fields
		if p.OIDC != nil {
			connector.Issuer = p.OIDC.Issuer
		}
		if p.LDAP != nil {
			connector.Servers = p.LDAP.Servers
		}

		connectors = append(connectors, connector)
	}

	return connectors, nil
}

// GetConnector returns a specific connector by ID
func (zm *ZitadelManager) GetConnector(ctx context.Context, connectorID string) (*Connector, error) {
	respBody, err := zm.get(ctx, fmt.Sprintf("idps/%s", connectorID), nil)
	if err != nil {
		return nil, fmt.Errorf("get connector: %w", err)
	}

	var resp struct {
		IDP zitadelProviderTemplate `json:"idp"`
	}
	if err := zm.helper.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal connector response: %w", err)
	}

	connector := &Connector{
		ID:    resp.IDP.ID,
		Name:  resp.IDP.Name,
		State: normalizeState(resp.IDP.State),
		Type:  normalizeType(resp.IDP.Type),
	}

	if resp.IDP.OIDC != nil {
		connector.Issuer = resp.IDP.OIDC.Issuer
	}
	if resp.IDP.LDAP != nil {
		connector.Servers = resp.IDP.LDAP.Servers
	}

	return connector, nil
}

// DeleteConnector removes an identity provider connector
func (zm *ZitadelManager) DeleteConnector(ctx context.Context, connectorID string) error {
	if err := zm.delete(ctx, fmt.Sprintf("idps/%s", connectorID)); err != nil {
		return fmt.Errorf("delete connector: %w", err)
	}
	return nil
}

// ActivateConnector adds the connector to the organization's login policy
func (zm *ZitadelManager) ActivateConnector(ctx context.Context, connectorID string) error {
	payload := map[string]string{
		"idpId": connectorID,
	}

	body, err := zm.helper.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal activate request: %w", err)
	}

	_, err = zm.post(ctx, "policies/login/idps", string(body))
	if err != nil {
		return fmt.Errorf("activate connector: %w", err)
	}

	return nil
}

// DeactivateConnector removes the connector from the organization's login policy
func (zm *ZitadelManager) DeactivateConnector(ctx context.Context, connectorID string) error {
	if err := zm.delete(ctx, fmt.Sprintf("policies/login/idps/%s", connectorID)); err != nil {
		return fmt.Errorf("deactivate connector: %w", err)
	}
	return nil
}

// normalizeState converts Zitadel state to a simple string
func normalizeState(state string) string {
	switch state {
	case "IDP_STATE_ACTIVE":
		return "active"
	case "IDP_STATE_INACTIVE":
		return "inactive"
	default:
		return state
	}
}

// normalizeType converts Zitadel type to ConnectorType
func normalizeType(idpType string) ConnectorType {
	switch idpType {
	case "IDP_TYPE_OIDC", "IDP_TYPE_OIDC_GENERIC":
		return ConnectorTypeOIDC
	case "IDP_TYPE_LDAP":
		return ConnectorTypeLDAP
	case "IDP_TYPE_SAML":
		return ConnectorTypeSAML
	default:
		return ConnectorType(idpType)
	}
}
