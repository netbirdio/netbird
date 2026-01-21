package proxy

import (
	"context"
)

type requestContextKey string

const (
	serviceIdKey requestContextKey = "serviceId"
)

func withServiceId(ctx context.Context, serviceId string) context.Context {
	return context.WithValue(ctx, serviceIdKey, serviceId)
}

func ServiceIdFromContext(ctx context.Context) string {
	v := ctx.Value(serviceIdKey)
	serviceId, ok := v.(string)
	if !ok {
		return ""
	}
	return serviceId
}
