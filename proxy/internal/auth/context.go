package auth

import (
	"context"

	"github.com/netbirdio/netbird/proxy/auth"
)

type requestContextKey string

const (
	authMethodKey requestContextKey = "authMethod"
	authUserKey   requestContextKey = "authUser"
)

func withAuthMethod(ctx context.Context, method auth.Method) context.Context {
	return context.WithValue(ctx, authMethodKey, method)
}

func MethodFromContext(ctx context.Context) auth.Method {
	v := ctx.Value(authMethodKey)
	method, ok := v.(auth.Method)
	if !ok {
		return ""
	}
	return method
}

func withAuthUser(ctx context.Context, userId string) context.Context {
	return context.WithValue(ctx, authUserKey, userId)
}

func UserFromContext(ctx context.Context) string {
	v := ctx.Value(authUserKey)
	userId, ok := v.(string)
	if !ok {
		return ""
	}
	return userId
}
