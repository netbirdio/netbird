package autonoma

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// AccountInput seeds one tenant. The owner is created in the embedded IdP with
// a password we choose, which is what lets the test runner sign in through the
// real login screen afterwards.
type AccountInput struct {
	// Domain is the account's email domain. Per-run so two concurrent runs
	// never get folded into one another's domain-primary account.
	Domain string `json:"domain"`
	// OwnerEmail must be unique across the whole IdP.
	OwnerEmail string `json:"ownerEmail"`
	OwnerName  string `json:"ownerName"`
	// OwnerPassword needs 8+ characters with a digit, an upper-case letter and
	// a symbol, matching the product's own password rules.
	OwnerPassword string `json:"ownerPassword"`
}

func (f *factories) accountFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *AccountInput, _ sdk.FactoryContext) (map[string]any, error) {
			embedded, err := f.embeddedIdp()
			if err != nil {
				return nil, err
			}

			owner, err := embedded.CreateUserWithPassword(ctx, in.OwnerEmail, in.OwnerPassword, in.OwnerName)
			if err != nil {
				return nil, fmt.Errorf("create the owner in the embedded IdP: %w", err)
			}

			// GetAccountIDByUserID creates the account for a user it has never
			// seen, which is the same path a first sign-in takes: it mints the
			// owner User, the account's IP network, the "All" group, the
			// settings and onboarding rows, and an AccountCreated event.
			accountID, err := f.deps.AccountManager.GetAccountIDByUserID(ctx, auth.UserAuth{
				UserId: owner.ID,
				Email:  in.OwnerEmail,
				Name:   in.OwnerName,
				Domain: in.Domain,
			})
			if err != nil {
				if delErr := embedded.DeleteUser(ctx, owner.ID); delErr != nil {
					return nil, fmt.Errorf("create account: %w (and rolling back the IdP user failed: %v)", err, delErr)
				}
				return nil, fmt.Errorf("create account: %w", err)
			}

			return map[string]any{
				"id":            accountID,
				"accountId":     accountID,
				"domain":        in.Domain,
				"ownerUserId":   owner.ID,
				"ownerEmail":    in.OwnerEmail,
				"ownerName":     in.OwnerName,
				"ownerPassword": in.OwnerPassword,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			// Deleting the account is the scoping-root teardown: it removes the
			// members (including their IdP users) and cascades into peers,
			// groups, policies, routes, nameservers, posture checks, networks,
			// services and domains - test-created rows the recipe never named
			// included.
			return f.deps.AccountManager.DeleteAccount(ctx, str(record, "id"), str(record, "ownerUserId"))
		},
	)
}

// UserInput adds a member to a seeded account.
type UserInput struct {
	AccountID string `json:"accountId"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	// Role is one of owner, admin, user, network_admin, billing_admin, auditor.
	Role string `json:"role"`
	// AutoGroups are group ids this user's peers join automatically.
	AutoGroups []string `json:"autoGroups,omitempty"`
	// Password, when set, routes creation through the invite-and-accept flow so
	// the member ends up with a password it can actually sign in with. Left
	// empty the member is created the way an admin invite creates one, with a
	// password only the IdP knows.
	Password string `json:"password,omitempty"`
}

func (f *factories) userFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *UserInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			info := &types.UserInfo{
				Email:      in.Email,
				Name:       in.Name,
				Role:       orDefaultStr(in.Role, string(types.UserRoleUser)),
				AutoGroups: strSlice(in.AutoGroups),
				Issued:     types.UserIssuedAPI,
			}

			if in.Password == "" {
				created, err := f.deps.AccountManager.CreateUser(ctx, in.AccountID, actor, info)
				if err != nil {
					return nil, fmt.Errorf("create user %s: %w", in.Email, err)
				}
				return userRecord(in.AccountID, created.ID, in.Email, in.Name, info.Role, ""), nil
			}

			// The invite link plus its acceptance is the product's own path to a
			// member with a chosen password, so use it rather than reaching into
			// the IdP directly. The invite row is consumed on acceptance.
			invite, err := f.deps.AccountManager.CreateUserInvite(ctx, in.AccountID, actor, info, types.DefaultInviteExpirationSeconds)
			if err != nil {
				return nil, fmt.Errorf("invite user %s: %w", in.Email, err)
			}
			if err := f.deps.AccountManager.AcceptUserInvite(ctx, invite.InviteToken, in.Password); err != nil {
				return nil, fmt.Errorf("accept the invite for %s: %w", in.Email, err)
			}

			created, err := f.userIDByEmail(ctx, in.AccountID, in.Email)
			if err != nil {
				return nil, err
			}
			return userRecord(in.AccountID, created, in.Email, in.Name, info.Role, in.Password), nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeleteUser(ctx, accountID, owner, str(record, "id"))
		},
	)
}

func userRecord(accountID, id, email, name, role, password string) map[string]any {
	return map[string]any{
		"id":        id,
		"accountId": accountID,
		"email":     email,
		"name":      name,
		"role":      role,
		"password":  password,
	}
}

func (f *factories) userIDByEmail(ctx context.Context, accountID, email string) (string, error) {
	users, err := f.deps.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return "", fmt.Errorf("read the account's users back: %w", err)
	}
	for _, user := range users {
		if strings.EqualFold(user.Email, email) {
			return user.Id, nil
		}
	}
	return "", fmt.Errorf("user %s was created but is not in account %s", email, accountID)
}

// PersonalAccessTokenInput mints an API token for a seeded member. A user can
// only mint their own token, so the token's owner is also its creator.
type PersonalAccessTokenInput struct {
	AccountID string `json:"accountId"`
	// UserID owns the token; empty means the account owner does.
	UserID string `json:"userId,omitempty"`
	Name   string `json:"name"`
	// ExpiresInDays is an offset, not a date: the row is written when the
	// scenario is seeded, so the token is always live for the run that uses it.
	// Between 1 and 365.
	ExpiresInDays int `json:"expiresInDays,omitempty"`
}

func (f *factories) personalAccessTokenFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *PersonalAccessTokenInput, fctx sdk.FactoryContext) (map[string]any, error) {
			userID := in.UserID
			if userID == "" {
				owner, err := f.actorFor(ctx, fctx, in.AccountID)
				if err != nil {
					return nil, err
				}
				userID = owner
			}

			pat, err := f.deps.AccountManager.CreatePAT(ctx, in.AccountID, userID, userID, in.Name, orDefaultInt(in.ExpiresInDays, 30))
			if err != nil {
				return nil, fmt.Errorf("create the personal access token %q: %w", in.Name, err)
			}
			return map[string]any{
				"id":        pat.ID,
				"accountId": in.AccountID,
				"userId":    userID,
				"name":      in.Name,
				"token":     pat.PlainToken,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			userID := str(record, "userId")
			return f.deps.AccountManager.DeletePAT(ctx, str(record, "accountId"), userID, userID, str(record, "id"))
		},
	)
}

// UserInviteRecordInput seeds a pending invitation - a member who has been
// invited but has not set a password yet.
type UserInviteRecordInput struct {
	AccountID string `json:"accountId"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	// ExpiresInSeconds is an offset from seeding time; the app hides invites
	// whose expiry has passed, so an absolute date here would rot. At least
	// 3600.
	ExpiresInSeconds int `json:"expiresInSeconds,omitempty"`
}

func (f *factories) userInviteFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *UserInviteRecordInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			invite, err := f.deps.AccountManager.CreateUserInvite(ctx, in.AccountID, actor, &types.UserInfo{
				Email:      in.Email,
				Name:       in.Name,
				Role:       orDefaultStr(in.Role, string(types.UserRoleUser)),
				AutoGroups: []string{},
				Issued:     types.UserIssuedAPI,
			}, orDefaultInt(in.ExpiresInSeconds, types.DefaultInviteExpirationSeconds))
			if err != nil {
				return nil, fmt.Errorf("create the invite for %s: %w", in.Email, err)
			}

			return map[string]any{
				"id":        invite.UserInfo.ID,
				"accountId": in.AccountID,
				"email":     in.Email,
				"token":     invite.InviteToken,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AccountManager.DeleteUserInvite(ctx, accountID, owner, str(record, "id"))
		},
	)
}

func (f *factories) embeddedIdp() (*idp.EmbeddedIdPManager, error) {
	embedded, ok := f.deps.IdpManager.(*idp.EmbeddedIdPManager)
	if !ok || embedded == nil {
		return nil, fmt.Errorf("seeding accounts needs the embedded identity provider; this deployment uses %T", f.deps.IdpManager)
	}
	return embedded, nil
}
