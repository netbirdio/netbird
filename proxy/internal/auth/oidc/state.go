package oidc

import "time"

// State represents stored OIDC state information for CSRF protection
type State struct {
	OriginalURL string
	CreatedAt   time.Time
	RouteID     string
}
