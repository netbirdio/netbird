package auth

import (
	"time"
)

type UserAuth struct {
	// The account id the user is accessing
	AccountId string
	// The account domain
	Domain string
	// The account domain category, TBC values
	DomainCategory string
	// Indicates whether this user was invited, TBC logic
	Invited bool
	// Indicates whether this is a child account
	IsChild bool

	// The user id
	UserId string
	// Last login time for this user
	LastLogin time.Time
	// The Groups the user belongs to on this account
	Groups []string

	// Indicates whether this user has authenticated with a Personal Access Token
	IsPAT bool
}
