package domain

type DomainType string

const (
	TypeFree   DomainType = "free"
	TypeCustom DomainType = "custom"
)

type Domain struct {
	ID            string     `gorm:"unique;primaryKey;autoIncrement"`
	Domain        string     `gorm:"unique"` // Domain records must be unique, this avoids domain reuse across accounts.
	AccountID     string     `gorm:"index"`
	TargetCluster string     // The proxy cluster this domain should be validated against
	Type          DomainType `gorm:"-"`
	Validated     bool
}
