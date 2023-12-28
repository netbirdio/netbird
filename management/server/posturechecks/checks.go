package posturechecks

import (
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type PostureChecker interface {
	Check(peer nbpeer.Peer) error
}

type PostureCheck struct {
	ID        string           `gorm:"primaryKey"`
	AccountID string           `gorm:"index"`
	PolicyID  string           `gorm:"index"`
	Checks    []PostureChecker `gorm:"serializer:json"`
}
