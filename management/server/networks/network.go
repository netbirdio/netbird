package networks

import "github.com/rs/xid"

type Network struct {
	ID          string `gorm:"index"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string
}

func NewNetwork(accountId, name, description string) *Network {
	return &Network{
		ID:          xid.New().String(),
		AccountID:   accountId,
		Name:        name,
		Description: description,
	}
}
