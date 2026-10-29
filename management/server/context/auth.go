package context

import (
	"context"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/shared/auth"
)

type key int

const (
	UserAuthContextKey key = iota
)

func GetUserAuthFromRequest(r *http.Request) (auth.UserAuth, error) {
	return GetUserAuthFromContext(r.Context())
}

func SetUserAuthInRequest(r *http.Request, userAuth auth.UserAuth) *http.Request {
	return r.WithContext(SetUserAuthInContext(r.Context(), userAuth))
}

func GetUserAuthFromContext(ctx context.Context) (auth.UserAuth, error) {
	if userAuth, ok := ctx.Value(UserAuthContextKey).(auth.UserAuth); ok {
		return userAuth, nil
	}
	return auth.UserAuth{}, fmt.Errorf("user auth not in context")
}

func SetUserAuthInContext(ctx context.Context, userAuth auth.UserAuth) context.Context {
	//nolint
	ctx = context.WithValue(ctx, UserIDKey, userAuth.UserId)
	//nolint
	ctx = context.WithValue(ctx, AccountIDKey, userAuth.AccountId)
	return context.WithValue(ctx, UserAuthContextKey, userAuth)
}
