package context

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type key int

const (
	UserAuthContextKey key = iota
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

func GetUserAuthFromRequest(r *http.Request) (UserAuth, error) {
	return GetUserAuthFromContext(r.Context())
}

func SetUserAuthInRequest(r *http.Request, userAuth UserAuth) *http.Request {
	return r.WithContext(SetUserAuthInContext(r.Context(), userAuth))
}

func GetUserAuthFromContext(ctx context.Context) (UserAuth, error) {
	if userAuth, ok := ctx.Value(UserAuthContextKey).(UserAuth); ok {
		return userAuth, nil
	}
	return UserAuth{}, fmt.Errorf("user auth not in context")
}

func SetUserAuthInContext(ctx context.Context, userAuth UserAuth) context.Context {
	//nolint
	ctx = context.WithValue(ctx, UserIDKey, userAuth.UserId)
	//nolint
	ctx = context.WithValue(ctx, AccountIDKey, userAuth.AccountId)
	return context.WithValue(ctx, UserAuthContextKey, userAuth)
}
