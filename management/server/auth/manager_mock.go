package auth

import (
	"context"

	"github.com/golang-jwt/jwt"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
)

var (
	_ Manager = (*MockManager)(nil)
)

// @note really dislike this mocking approach but rather than have to do additional test refactoring.
type MockManager struct {
	ValidateAndParseTokenFunc       func(ctx context.Context, value string) (nbcontext.UserAuth, *jwt.Token, error)
	EnsureUserAccessByJWTGroupsFunc func(ctx context.Context, userAuth nbcontext.UserAuth, token *jwt.Token) (nbcontext.UserAuth, error)
	MarkPATUsedFunc                 func(ctx context.Context, tokenID string) error
	GetPATInfoFunc                  func(ctx context.Context, token string) (user *types.User, pat *types.PersonalAccessToken, domain string, category string, err error)
}

// EnsureUserAccessByJWTGroups implements Manager.
func (m *MockManager) EnsureUserAccessByJWTGroups(ctx context.Context, userAuth nbcontext.UserAuth, token *jwt.Token) (nbcontext.UserAuth, error) {
	if m.EnsureUserAccessByJWTGroupsFunc != nil {
		return m.EnsureUserAccessByJWTGroupsFunc(ctx, userAuth, token)
	}
	return nbcontext.UserAuth{}, nil
}

// GetPATInfo implements Manager.
func (m *MockManager) GetPATInfo(ctx context.Context, token string) (user *types.User, pat *types.PersonalAccessToken, domain string, category string, err error) {
	if m.GetPATInfoFunc != nil {
		return m.GetPATInfoFunc(ctx, token)
	}
	return &types.User{}, &types.PersonalAccessToken{}, "", "", nil
}

// MarkPATUsed implements Manager.
func (m *MockManager) MarkPATUsed(ctx context.Context, tokenID string) error {
	if m.MarkPATUsedFunc != nil {
		return m.MarkPATUsedFunc(ctx, tokenID)
	}
	return nil
}

// ValidateAndParseToken implements Manager.
func (m *MockManager) ValidateAndParseToken(ctx context.Context, value string) (nbcontext.UserAuth, *jwt.Token, error) {
	if m.ValidateAndParseTokenFunc != nil {
		return m.ValidateAndParseTokenFunc(ctx, value)
	}
	return nbcontext.UserAuth{}, &jwt.Token{}, nil
}
