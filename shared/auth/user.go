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
	// The user's email address
	// (optional, may be empty if not in token, make sure to set getUserInfo: true in Dex to have this field)
	Email string
	// The user's name
	// (optional, may be empty if not in token, make sure to set getUserInfo: true in Dex to have this field)
	Name string
	// The user's preferred name
	// (optional, may be empty if not in token, make sure to set getUserInfo: true in Dex to have this field)
	PreferredName string
	// Last login time for this user
	LastLogin time.Time
	// The Groups the user belongs to on this account
	Groups []string

	// Indicates whether this user has authenticated with a Personal Access Token
	IsPAT bool
}
