package types

type Policy interface {
	GetID() string
}

type DefaultPolicy struct {
	ID string
}

func (dp *DefaultPolicy) GetID() string {
	return dp.ID
}
