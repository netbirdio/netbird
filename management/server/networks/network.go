package networks

import "github.com/rs/xid"

type Network struct {
	ID          string `gorm:"index"`
	Name        string
	Description string
}

func NewNetwork(name, description string) *Network {
	return &Network{
		ID:          xid.New().String(),
		Name:        name,
		Description: description,
	}
}
