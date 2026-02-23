# Self-Service Authentication Implementation Plan

## Overview

Replace the current IdP-dependent authentication system with a generic OIDC approach featuring:
- Local admin user created on first boot
- Admin-configured OIDC providers
- Self-service user registration with admin approval
- Local storage of user email/name (from OIDC userinfo endpoint)

---

## Current State vs. Target State

| Aspect | Current | Target |
|--------|---------|--------|
| Initial admin | Created via IdP | Generated locally on first boot |
| User email/name | Fetched from IdP API, cached | Extracted from OIDC userinfo, stored in DB |
| User invitation | IdP creates user, sends email | Self-service: user logs in, admin approves |
| IdP integration | 9 specific implementations | Generic OIDC client |
| User storage | ID only (email from cache) | ID, email, name, auth_provider stored locally |

---

## Phase 1: Database Schema Changes

### 1.1 Modify User Model

**File:** `management/server/types/user.go`

Add new fields to the `User` struct:

```go
type User struct {
    Id              string    `gorm:"primaryKey"`
    AccountID       string    `gorm:"index"`
    Role            UserRole
    IsServiceUser   bool
    NonDeletable    bool
    ServiceUserName string
    AutoGroups      []string  `gorm:"serializer:json"`
    Blocked         bool
    LastLogin       *time.Time
    CreatedAt       time.Time
    Issued          string    `gorm:"default:api"`

    // NEW FIELDS
    Email           string    `gorm:"index"`           // Stored locally now
    Name            string                              // Display name
    PasswordHash    string    `json:"-"`               // For local admin users only
    AuthProvider    string    `gorm:"default:local"`   // "local" or OIDC provider ID
    ProviderUserID  string    `gorm:"index"`           // External user ID from OIDC provider
    Status          UserStatus `gorm:"default:pending"` // pending, active, blocked
    ApprovedBy      string                              // UserID who approved
    ApprovedAt      *time.Time

    // KEEP EXISTING
    PATsG           []PersonalAccessToken `gorm:"foreignKey:UserID"`
    IntegrationReference integration_reference.IntegrationReference `gorm:"embedded"`
}
```

**New UserStatus values:**
```go
const (
    UserStatusPending  UserStatus = "pending"   // Awaiting admin approval
    UserStatusActive   UserStatus = "active"    // Approved and can access
    UserStatusBlocked  UserStatus = "blocked"   // Blocked by admin
)
```

### 1.2 Add OIDC Provider Model

**File:** `management/server/types/oidc_provider.go` (NEW)

```go
package types

import "time"

type OIDCProvider struct {
    ID           string    `gorm:"primaryKey"`
    AccountID    string    `gorm:"index"`
    Name         string                        // Display name: "Login with <Name>"
    Issuer       string                        // OIDC issuer URL
    ClientID     string
    ClientSecret string    `json:"-"`          // Encrypted at rest
    Enabled      bool      `gorm:"default:true"`
    CreatedAt    time.Time
    UpdatedAt    time.Time

    // Claim configuration (with sensible defaults)
    UserIDClaim  string    `gorm:"default:sub"`
    EmailClaim   string    `gorm:"default:email"`
    NameClaim    string    `gorm:"default:name"`
}
```

### 1.3 Database Migration

**File:** `management/server/store/sql_store.go`

Add to AutoMigrate list (around line 111):
```go
err = db.AutoMigrate(
    // ... existing models ...
    &types.OIDCProvider{},  // NEW
)
```

Add migration for existing users:
```go
// Migration: Set existing users to active status and local provider
func migrateExistingUsersToNewSchema(db *gorm.DB) error {
    return db.Model(&types.User{}).
        Where("status = '' OR status IS NULL").
        Updates(map[string]interface{}{
            "status":        types.UserStatusActive,
            "auth_provider": "legacy_idp",
        }).Error
}
```

---

## Phase 2: Local Admin Bootstrap

### 2.1 Admin Generation on First Boot

**File:** `management/server/account.go`

Add function to create initial admin:

```go
func (am *DefaultAccountManager) BootstrapLocalAdmin(ctx context.Context) error {
    // Check if any admin user exists
    accounts := am.Store.GetAllAccounts(ctx)
    if len(accounts) > 0 {
        return nil // Already bootstrapped
    }

    // Get credentials from environment
    adminEmail := os.Getenv("NETBIRD_ADMIN_EMAIL")
    adminPassword := os.Getenv("NETBIRD_ADMIN_PASSWORD")

    if adminEmail == "" || adminPassword == "" {
        // Generate random password if not provided
        adminEmail = "admin@netbird.local"
        adminPassword = generateSecurePassword(24)
        log.Warnf("Generated admin credentials - Email: %s, Password: %s",
                  adminEmail, adminPassword)
        log.Warn("Please change this password immediately!")
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword(
        []byte(adminPassword),
        bcrypt.DefaultCost,
    )
    if err != nil {
        return fmt.Errorf("failed to hash password: %w", err)
    }

    // Create account
    accountID := xid.New().String()
    userID := xid.New().String()

    account := newAccountWithId(ctx, accountID, userID, "")
    account.Domain = "netbird.local"
    account.DomainCategory = types.PrivateCategory

    // Create admin user
    adminUser := &types.User{
        Id:           userID,
        AccountID:    accountID,
        Email:        adminEmail,
        Name:         "Administrator",
        Role:         types.UserRoleOwner,
        PasswordHash: string(hashedPassword),
        AuthProvider: "local",
        Status:       types.UserStatusActive,
        CreatedAt:    time.Now().UTC(),
        Issued:       "bootstrap",
    }

    account.Users[userID] = adminUser

    if err := am.Store.SaveAccount(ctx, account); err != nil {
        return fmt.Errorf("failed to save account: %w", err)
    }

    log.Infof("Created initial admin account: %s", adminEmail)
    return nil
}
```

### 2.2 Call Bootstrap on Server Start

**File:** `management/cmd/management.go`

Add after account manager creation:

```go
// Bootstrap local admin if first run
if err := accountManager.BootstrapLocalAdmin(ctx); err != nil {
    return fmt.Errorf("failed to bootstrap admin: %w", err)
}
```

### 2.3 Local Login Endpoint

**File:** `management/server/http/handlers/auth/local_auth_handler.go` (NEW)

```go
package auth

type LocalLoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type LocalLoginResponse struct {
    Token     string `json:"token"`
    ExpiresAt int64  `json:"expires_at"`
}

func (h *AuthHandler) LocalLogin(w http.ResponseWriter, r *http.Request) {
    var req LocalLoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // Find user by email
    user, err := h.accountManager.GetUserByEmail(r.Context(), req.Email)
    if err != nil {
        util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "invalid credentials"), w)
        return
    }

    // Check if local auth is allowed
    if user.AuthProvider != "local" {
        util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "use SSO login"), w)
        return
    }

    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "invalid credentials"), w)
        return
    }

    // Check user status
    if user.Status != types.UserStatusActive {
        util.WriteError(r.Context(), status.Errorf(status.Forbidden, "account not active"), w)
        return
    }

    // Generate JWT token (signed by NetBird)
    token, expiresAt, err := h.authManager.GenerateToken(user)
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // Update last login
    h.accountManager.UpdateUserLastLogin(r.Context(), user.AccountID, user.Id)

    util.WriteJSONObject(r.Context(), w, &LocalLoginResponse{
        Token:     token,
        ExpiresAt: expiresAt,
    })
}
```

---

## Phase 3: OIDC Provider Management

### 3.1 OIDC Provider Store Methods

**File:** `management/server/store/store.go`

Add to Store interface:

```go
type Store interface {
    // ... existing methods ...

    // OIDC Provider methods
    GetOIDCProviders(ctx context.Context, accountID string) ([]*types.OIDCProvider, error)
    GetOIDCProviderByID(ctx context.Context, accountID, providerID string) (*types.OIDCProvider, error)
    SaveOIDCProvider(ctx context.Context, provider *types.OIDCProvider) error
    DeleteOIDCProvider(ctx context.Context, accountID, providerID string) error
}
```

### 3.2 OIDC Provider API Endpoints

**File:** `management/server/http/handlers/oidc/oidc_provider_handler.go` (NEW)

```go
package oidc

// Endpoints (admin only):
// GET    /api/oidc-providers          - List all providers for account
// POST   /api/oidc-providers          - Add new provider
// PUT    /api/oidc-providers/{id}     - Update provider
// DELETE /api/oidc-providers/{id}     - Delete provider

type CreateOIDCProviderRequest struct {
    Name         string `json:"name"`          // "Google", "Okta", etc.
    Issuer       string `json:"issuer"`        // https://accounts.google.com
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
    UserIDClaim  string `json:"user_id_claim,omitempty"`  // defaults to "sub"
    EmailClaim   string `json:"email_claim,omitempty"`    // defaults to "email"
    NameClaim    string `json:"name_claim,omitempty"`     // defaults to "name"
}

func (h *OIDCProviderHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
    // 1. Validate admin permissions
    // 2. Parse request
    // 3. Validate OIDC discovery (fetch .well-known/openid-configuration)
    // 4. Save provider
    // 5. Return created provider (without secret)
}
```

### 3.3 Public Endpoint: List Available Providers

**File:** `management/server/http/handlers/auth/providers_handler.go` (NEW)

```go
// GET /api/auth/providers - PUBLIC endpoint (no auth required)
// Returns list of enabled OIDC providers for login page

type AvailableProvider struct {
    ID       string `json:"id"`
    Name     string `json:"name"`        // "Login with Google"
    AuthURL  string `json:"auth_url"`    // Authorization endpoint
}

func (h *AuthHandler) GetAvailableProviders(w http.ResponseWriter, r *http.Request) {
    // For single-account mode, get providers from that account
    // Otherwise, this might need account context from domain/subdomain

    providers, err := h.accountManager.GetEnabledOIDCProviders(r.Context())
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    var available []AvailableProvider
    for _, p := range providers {
        authURL := buildAuthorizationURL(p)
        available = append(available, AvailableProvider{
            ID:      p.ID,
            Name:    p.Name,
            AuthURL: authURL,
        })
    }

    // Include local login option if any local users exist
    hasLocalUsers, _ := h.accountManager.HasLocalUsers(r.Context())

    util.WriteJSONObject(r.Context(), w, map[string]interface{}{
        "providers":       available,
        "local_login":     hasLocalUsers,
    })
}
```

---

## Phase 4: OIDC Authentication Flow

### 4.1 Generic OIDC Client

**File:** `management/server/oidc/client.go` (NEW)

```go
package oidc

import (
    "context"
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

type Client struct {
    provider *oidc.Provider
    config   oauth2.Config
    verifier *oidc.IDTokenVerifier

    // Claim configuration
    userIDClaim string
    emailClaim  string
    nameClaim   string
}

type UserInfo struct {
    ProviderUserID string
    Email          string
    Name           string
    RawClaims      map[string]interface{}
}

func NewClient(ctx context.Context, providerConfig *types.OIDCProvider, redirectURL string) (*Client, error) {
    // Discover OIDC configuration
    provider, err := oidc.NewProvider(ctx, providerConfig.Issuer)
    if err != nil {
        return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
    }

    config := oauth2.Config{
        ClientID:     providerConfig.ClientID,
        ClientSecret: providerConfig.ClientSecret,
        RedirectURL:  redirectURL,
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
    }

    verifier := provider.Verifier(&oidc.Config{
        ClientID: providerConfig.ClientID,
    })

    return &Client{
        provider:    provider,
        config:      config,
        verifier:    verifier,
        userIDClaim: providerConfig.UserIDClaim,
        emailClaim:  providerConfig.EmailClaim,
        nameClaim:   providerConfig.NameClaim,
    }, nil
}

func (c *Client) GetAuthorizationURL(state string) string {
    return c.config.AuthCodeURL(state)
}

func (c *Client) ExchangeCode(ctx context.Context, code string) (*UserInfo, error) {
    // Exchange code for tokens
    token, err := c.config.Exchange(ctx, code)
    if err != nil {
        return nil, fmt.Errorf("code exchange failed: %w", err)
    }

    // Get userinfo from endpoint (more reliable than token claims)
    userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
    if err != nil {
        return nil, fmt.Errorf("failed to get userinfo: %w", err)
    }

    // Extract claims
    var claims map[string]interface{}
    if err := userInfo.Claims(&claims); err != nil {
        return nil, fmt.Errorf("failed to parse claims: %w", err)
    }

    return &UserInfo{
        ProviderUserID: extractClaim(claims, c.userIDClaim, "sub"),
        Email:          extractClaim(claims, c.emailClaim, "email"),
        Name:           extractClaim(claims, c.nameClaim, "name"),
        RawClaims:      claims,
    }, nil
}

func extractClaim(claims map[string]interface{}, preferred, fallback string) string {
    if val, ok := claims[preferred].(string); ok && val != "" {
        return val
    }
    if val, ok := claims[fallback].(string); ok {
        return val
    }
    return ""
}
```

### 4.2 OIDC Callback Handler

**File:** `management/server/http/handlers/auth/oidc_callback_handler.go` (NEW)

```go
package auth

// GET /api/auth/oidc/{providerId}/callback?code=xxx&state=xxx

func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
    providerID := mux.Vars(r)["providerId"]
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")

    // 1. Validate state (CSRF protection)
    if !h.validateState(state) {
        http.Error(w, "invalid state", http.StatusBadRequest)
        return
    }

    // 2. Get provider configuration
    provider, err := h.accountManager.GetOIDCProvider(r.Context(), providerID)
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // 3. Create OIDC client and exchange code
    client, err := oidc.NewClient(r.Context(), provider, h.getRedirectURL(providerID))
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    userInfo, err := client.ExchangeCode(r.Context(), code)
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // 4. Find or create user
    user, isNew, err := h.accountManager.GetOrCreateOIDCUser(r.Context(), provider.AccountID, &types.OIDCUserInfo{
        ProviderID:     providerID,
        ProviderUserID: userInfo.ProviderUserID,
        Email:          userInfo.Email,
        Name:           userInfo.Name,
    })
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // 5. Check user status
    if user.Status == types.UserStatusPending {
        // Redirect to "pending approval" page
        http.Redirect(w, r, "/auth/pending-approval", http.StatusFound)
        return
    }

    if user.Status == types.UserStatusBlocked {
        http.Error(w, "account blocked", http.StatusForbidden)
        return
    }

    // 6. Generate NetBird JWT
    token, expiresAt, err := h.authManager.GenerateToken(user)
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // 7. Update last login
    h.accountManager.UpdateUserLastLogin(r.Context(), user.AccountID, user.Id)

    // 8. Redirect to dashboard with token
    redirectURL := fmt.Sprintf("/auth/callback?token=%s&expires=%d&new=%t",
        token, expiresAt, isNew)
    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

### 4.3 User Creation/Lookup for OIDC Users

**File:** `management/server/account.go`

```go
type OIDCUserInfo struct {
    ProviderID     string
    ProviderUserID string
    Email          string
    Name           string
}

func (am *DefaultAccountManager) GetOrCreateOIDCUser(
    ctx context.Context,
    accountID string,
    info *OIDCUserInfo,
) (*types.User, bool, error) {

    // Try to find existing user by provider + provider user ID
    user, err := am.Store.GetUserByProviderID(ctx, accountID, info.ProviderID, info.ProviderUserID)
    if err == nil {
        // User exists - update email/name if changed
        if user.Email != info.Email || user.Name != info.Name {
            user.Email = info.Email
            user.Name = info.Name
            am.Store.SaveUser(ctx, user)
        }
        return user, false, nil
    }

    // Check if user with same email exists (different provider)
    existingUser, err := am.Store.GetUserByEmail(ctx, accountID, info.Email)
    if err == nil {
        // Link this provider to existing user? Or reject?
        // For now, reject - admin must handle manually
        return nil, false, status.Errorf(status.Conflict,
            "user with email %s already exists with different provider", info.Email)
    }

    // Create new user with pending status
    newUser := &types.User{
        Id:             xid.New().String(),
        AccountID:      accountID,
        Email:          info.Email,
        Name:           info.Name,
        Role:           types.UserRoleUnknown,  // No role until approved
        AuthProvider:   info.ProviderID,
        ProviderUserID: info.ProviderUserID,
        Status:         types.UserStatusPending,
        CreatedAt:      time.Now().UTC(),
        Issued:         "oidc",
    }

    if err := am.Store.SaveUser(ctx, newUser); err != nil {
        return nil, false, err
    }

    // Log activity
    am.StoreEvent(ctx, newUser.Id, accountID, activity.UserRegistered,
        map[string]any{"email": info.Email, "provider": info.ProviderID})

    // TODO: Notify admins of new pending user

    return newUser, true, nil
}
```

---

## Phase 5: User Approval System

### 5.1 Approval Endpoints

**File:** `management/server/http/handlers/users/users_handler.go`

Add new endpoints:

```go
// GET  /api/users/pending           - List pending users (admin only)
// POST /api/users/{userId}/approve  - Approve user and assign role
// POST /api/users/{userId}/reject   - Reject/delete pending user

type ApproveUserRequest struct {
    Role string `json:"role"`  // "user" or "admin"
}

func (h *UsersHandler) ApproveUser(w http.ResponseWriter, r *http.Request) {
    userID := mux.Vars(r)["userId"]

    var req ApproveUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    // Validate role
    role := types.StrRoleToUserRole(req.Role)
    if role == types.UserRoleUnknown {
        util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid role"), w)
        return
    }

    // Get current user (admin)
    claims := h.claimsExtractor.FromRequestContext(r)

    // Approve the user
    user, err := h.accountManager.ApproveUser(r.Context(), claims.AccountID, claims.UserID, userID, role)
    if err != nil {
        util.WriteError(r.Context(), err, w)
        return
    }

    util.WriteJSONObject(r.Context(), w, toUserResponse(user))
}
```

### 5.2 Approval Business Logic

**File:** `management/server/user.go`

```go
func (am *DefaultAccountManager) ApproveUser(
    ctx context.Context,
    accountID, approverID, userID string,
    role types.UserRole,
) (*types.User, error) {

    // Validate approver has permission
    approver, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, approverID)
    if err != nil {
        return nil, err
    }

    if !approver.HasAdminPower() {
        return nil, status.Errorf(status.PermissionDenied, "only admins can approve users")
    }

    // Get pending user
    user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
    if err != nil {
        return nil, err
    }

    if user.AccountID != accountID {
        return nil, status.Errorf(status.NotFound, "user not found")
    }

    if user.Status != types.UserStatusPending {
        return nil, status.Errorf(status.PreconditionFailed, "user is not pending approval")
    }

    // Approve
    now := time.Now().UTC()
    user.Status = types.UserStatusActive
    user.Role = role
    user.ApprovedBy = approverID
    user.ApprovedAt = &now

    if err := am.Store.SaveUser(ctx, user); err != nil {
        return nil, err
    }

    // Log activity
    am.StoreEvent(ctx, approverID, accountID, activity.UserApproved,
        map[string]any{"user_id": userID, "email": user.Email, "role": string(role)})

    // TODO: Notify user they've been approved (email?)

    return user, nil
}

func (am *DefaultAccountManager) GetPendingUsers(ctx context.Context, accountID string) ([]*types.User, error) {
    return am.Store.GetUsersByStatus(ctx, accountID, types.UserStatusPending)
}
```

---

## Phase 6: Token Generation (NetBird-Signed JWTs)

### 6.1 JWT Signing Key Management

**File:** `management/server/auth/jwt_issuer.go` (NEW)

```go
package auth

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

type JWTIssuer struct {
    privateKey *ecdsa.PrivateKey
    publicKey  *ecdsa.PublicKey
    issuer     string
    audience   string
}

func NewJWTIssuer(issuer, audience string) (*JWTIssuer, error) {
    // TODO: Load from persistent storage or generate new
    // For production, key should be stored encrypted in DB or HSM
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    return &JWTIssuer{
        privateKey: privateKey,
        publicKey:  &privateKey.PublicKey,
        issuer:     issuer,
        audience:   audience,
    }, nil
}

func (j *JWTIssuer) GenerateToken(user *types.User) (string, int64, error) {
    expiresAt := time.Now().Add(24 * time.Hour)

    claims := jwt.MapClaims{
        "sub":       user.Id,
        "email":     user.Email,
        "name":      user.Name,
        "account_id": user.AccountID,
        "role":      string(user.Role),
        "iss":       j.issuer,
        "aud":       j.audience,
        "iat":       time.Now().Unix(),
        "exp":       expiresAt.Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
    tokenString, err := token.SignedString(j.privateKey)
    if err != nil {
        return "", 0, err
    }

    return tokenString, expiresAt.Unix(), nil
}

// GetJWKS returns the public key in JWKS format for token verification
func (j *JWTIssuer) GetJWKS() map[string]interface{} {
    // Return JWKS-formatted public key
    // This endpoint allows the auth middleware to verify NetBird-issued tokens
}
```

### 6.2 JWKS Endpoint

**File:** `management/server/http/handlers/auth/jwks_handler.go` (NEW)

```go
// GET /.well-known/jwks.json - Public endpoint for token verification

func (h *AuthHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
    jwks := h.jwtIssuer.GetJWKS()
    util.WriteJSONObject(r.Context(), w, jwks)
}
```

---

## Phase 7: Update Auth Middleware

### 7.1 Support Both External and Internal JWTs

**File:** `management/server/http/middleware/auth_middleware.go`

Modify to support NetBird-issued tokens:

```go
func (m *AuthMiddleware) checkJWTFromRequest(w http.ResponseWriter, r *http.Request) error {
    token := extractToken(r)

    // Try to validate as NetBird-issued token first
    userAuth, jwtToken, err := m.authManager.ValidateAndParseToken(r.Context(), token)
    if err != nil {
        // If validation fails, might be external OIDC token
        // But in new flow, all API access uses NetBird tokens
        return err
    }

    // Check user status
    user, err := m.getUserFromAuth(r.Context(), userAuth)
    if err != nil {
        return err
    }

    if user.Status != types.UserStatusActive {
        return status.Errorf(status.Forbidden, "user not active")
    }

    // Continue with existing flow...
}
```

---

## Phase 8: Remove/Deprecate IdP Manager

### 8.1 Make IdP Manager Optional

**File:** `management/server/account.go`

The IdP manager (`am.idpManager`) should become optional:

```go
func NewDefaultAccountManager(...) (*DefaultAccountManager, error) {
    // ...

    // IdP manager is now optional - only needed for legacy support
    if config.IdpManagerConfig != nil && config.IdpManagerConfig.ManagerType != "" {
        idpManager, err := idp.NewManager(ctx, *config.IdpManagerConfig, appMetrics)
        if err != nil {
            log.Warnf("IdP manager not configured: %v", err)
        }
        am.idpManager = idpManager
    }

    // ...
}
```

### 8.2 Update User Info Retrieval

**File:** `management/server/user.go`

`ToUserInfo` no longer needs IdP data:

```go
func (u *User) ToUserInfo(userData *idp.UserData) (*UserInfo, error) {
    // Email and name now come from local User, not IdP
    return &UserInfo{
        ID:         u.Id,
        Email:      u.Email,      // Now stored locally!
        Name:       u.Name,       // Now stored locally!
        Role:       string(u.Role),
        Status:     string(u.Status),
        // ...
    }, nil
}
```

---

## Phase 9: API Route Summary

### Public Endpoints (No Auth)
```
GET  /api/auth/providers                    - List available login methods
POST /api/auth/local/login                  - Local admin login
GET  /api/auth/oidc/{providerId}/callback   - OIDC callback handler
GET  /.well-known/jwks.json                 - Public keys for token verification
```

### Authenticated Endpoints
```
# User management (admin only)
GET    /api/users/pending                   - List pending users
POST   /api/users/{userId}/approve          - Approve user
POST   /api/users/{userId}/reject           - Reject user
DELETE /api/users/{userId}                  - Delete user
PUT    /api/users/{userId}                  - Update user (role, block, etc.)

# OIDC provider management (admin only)
GET    /api/oidc-providers                  - List providers
POST   /api/oidc-providers                  - Add provider
PUT    /api/oidc-providers/{id}             - Update provider
DELETE /api/oidc-providers/{id}             - Delete provider

# Existing endpoints remain unchanged
GET    /api/accounts                        - Get account info
GET    /api/peers                           - List peers
# ... etc
```

---

## Security Considerations

### Password Storage
- Use bcrypt with cost factor 12+ for local admin passwords
- Never log or return passwords in API responses

### OIDC State Parameter
- Generate cryptographically secure random state
- Store in server-side session or signed cookie
- Validate on callback to prevent CSRF

### Token Security
- NetBird-issued JWTs should be short-lived (1-24 hours)
- Consider refresh token mechanism for longer sessions
- Store signing keys securely (encrypted at rest)

### Email Privacy
- Question: Should we hash/obscure emails in DB?
- Recommendation: **No** - admins need to see emails to approve users
- Do: Encrypt database at rest, use TLS for all connections

### Rate Limiting
- Add rate limiting to login endpoints
- Prevent brute force attacks on local admin

---

## Migration Path

### For Existing Deployments

1. **Database migration** runs automatically on upgrade
2. **Existing users** get `status: active`, `auth_provider: legacy_idp`
3. **Existing IdP config** continues to work (backward compatible)
4. **Admin can add OIDC providers** alongside existing IdP
5. **Gradual migration**: New users use new flow, existing users continue with IdP

### Breaking Changes

- New users no longer created in IdP
- Invitation flow removed (replaced with self-service + approval)
- IdP API credentials no longer required (but still supported)

---

## Implementation Order

1. **Phase 1**: Database schema changes (foundation)
2. **Phase 2**: Local admin bootstrap (enables testing)
3. **Phase 6**: Token generation (needed for auth)
4. **Phase 7**: Update auth middleware (enables local login)
5. **Phase 3**: OIDC provider management (admin can configure)
6. **Phase 4**: OIDC authentication flow (users can login)
7. **Phase 5**: User approval system (admin can approve)
8. **Phase 8**: Deprecate IdP manager (cleanup)
9. **Phase 9**: Dashboard updates (outside this scope)

---

## Testing Plan

### Unit Tests
- Password hashing/verification
- JWT generation/validation
- OIDC client (mock provider)
- User approval logic

### Integration Tests
- Full OIDC flow with test provider
- Local admin login flow
- User registration and approval flow
- Token refresh and expiration

### Manual Testing
- Test with real OIDC providers (Google, Okta, Keycloak)
- Test migration from existing deployment
- Test multi-provider scenarios

---

## Open Questions

1. **Multiple accounts**: How does OIDC flow work without single-account mode?
   - Option: Require single-account mode for new auth system
   - Option: Use email domain to determine account

2. **Email verification**: Should we verify email ownership?
   - OIDC providers typically verify email
   - Could add optional email verification for extra security

3. **Password reset for local admin**:
   - Option: Env var override on restart
   - Option: Recovery codes generated at bootstrap
   - Option: Separate CLI command

4. **Session management**:
   - Current: Stateless JWTs
   - Consider: Server-side sessions for revocation capability

5. **Audit logging**: What events to log?
   - User registration, approval, rejection
   - Login attempts (success/failure)
   - Role changes, user blocking