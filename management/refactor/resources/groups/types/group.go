package types

type Group interface {
}

type DefaultGroup struct {
	// ID of the group
	ID string

	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Name visible in the UI
	Name string

	// Issued of the group
	Issued string

	// Peers list of the group
	Peers []string `gorm:"serializer:json"`

	IntegrationReference IntegrationReference `gorm:"embedded;embeddedPrefix:integration_ref_"`
}
