package auth

import (
	"context"
)

type requestContextKey string

const (
	authMethodKey requestContextKey = "authMethod"
	authUserKey   requestContextKey = "authUser"
)

func withAuthMethod(ctx context.Context, method Method) context.Context {
	return context.WithValue(ctx, authMethodKey, method)
}

func MethodFromContext(ctx context.Context) Method {
	v := ctx.Value(authMethodKey)
	method, ok := v.(Method)
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
