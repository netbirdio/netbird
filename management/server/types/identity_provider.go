package types

// IdentityProviderType is the type of identity provider
type IdentityProviderType string

const (
	// IdentityProviderTypeOIDC is a generic OIDC identity provider
	IdentityProviderTypeOIDC IdentityProviderType = "oidc"
	// IdentityProviderTypeZitadel is the Zitadel identity provider
	IdentityProviderTypeZitadel IdentityProviderType = "zitadel"
	// IdentityProviderTypeEntra is the Microsoft Entra (Azure AD) identity provider
	IdentityProviderTypeEntra IdentityProviderType = "entra"
	// IdentityProviderTypeGoogle is the Google identity provider
	IdentityProviderTypeGoogle IdentityProviderType = "google"
	// IdentityProviderTypeOkta is the Okta identity provider
	IdentityProviderTypeOkta IdentityProviderType = "okta"
	// IdentityProviderTypePocketID is the PocketID identity provider
	IdentityProviderTypePocketID IdentityProviderType = "pocketid"
	// IdentityProviderTypeMicrosoft is the Microsoft identity provider
	IdentityProviderTypeMicrosoft IdentityProviderType = "microsoft"
)

// IdentityProvider represents an identity provider configuration
type IdentityProvider struct {
	// ID is the unique identifier of the identity provider
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`
	// Type is the type of identity provider
	Type IdentityProviderType
	// Name is a human-readable name for the identity provider
	Name string
	// Issuer is the OIDC issuer URL
	Issuer string
	// ClientID is the OAuth2 client ID
	ClientID string
	// ClientSecret is the OAuth2 client secret
	ClientSecret string
}

// Copy returns a copy of the IdentityProvider
func (idp *IdentityProvider) Copy() *IdentityProvider {
	return &IdentityProvider{
		ID:           idp.ID,
		AccountID:    idp.AccountID,
		Type:         idp.Type,
		Name:         idp.Name,
		Issuer:       idp.Issuer,
		ClientID:     idp.ClientID,
		ClientSecret: idp.ClientSecret,
	}
}

// EventMeta returns a map of metadata for activity events
func (idp *IdentityProvider) EventMeta() map[string]any {
	return map[string]any{
		"name":   idp.Name,
		"type":   string(idp.Type),
		"issuer": idp.Issuer,
	}
}
