package types

type PolicyRule interface {
	GetID() string
}

type DefaultPolicyRule struct {
	ID string
}

func (dpr *DefaultPolicyRule) GetID() string {
	return dpr.ID
}
