package users

import "time"

// UserRole is the role of a User
type UserRole string

type User interface {
	IsBlocked() bool
}

// User represents a user of the system
type DefaultUser struct {
	Id string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID     string `json:"-" gorm:"index"`
	Role          UserRole
	IsServiceUser bool
	// NonDeletable indicates whether the service user can be deleted
	NonDeletable bool
	// ServiceUserName is only set if IsServiceUser is true
	ServiceUserName string
	// AutoGroups is a list of Group IDs to auto-assign to peers registered by this user
	AutoGroups []string `gorm:"serializer:json"`
	// Blocked indicates whether the user is blocked. Blocked users can't use the system.
	Blocked bool
	// LastLogin is the last time the user logged in to IdP
	LastLogin time.Time
	// Issued of the user
	Issued string `gorm:"default:api"`
}

func (u *DefaultUser) IsBlocked() bool {
	return u.Blocked
}
