package domain

type Type string

const (
	TypeFree   Type = "free"
	TypeCustom Type = "custom"
)

type Domain struct {
	ID            string `gorm:"unique;primaryKey;autoIncrement"`
	Domain        string `gorm:"unique"` // Domain records must be unique, this avoids domain reuse across accounts.
	AccountID     string `gorm:"index"`
	TargetCluster string // The proxy cluster this domain should be validated against
	Type          Type   `gorm:"-"`
	Validated     bool
}
