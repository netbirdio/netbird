package auth

import (
	"context"
	"net/http"
	"net/url"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/auth/jwt"
)

type urlGenerator interface {
	GetOIDCURL(context.Context, *proto.GetOIDCURLRequest, ...grpc.CallOption) (*proto.GetOIDCURLResponse, error)
}

// OIDCConfig holds configuration for OIDC JWT verification
type OIDCConfig struct {
	Issuer             string
	Audiences          []string
	KeysLocation       string
	MaxTokenAgeSeconds int64
}

// oidcState stores CSRF state with expiration
type oidcState struct {
	OriginalURL string
	CreatedAt   time.Time
}

// OIDC implements the Scheme interface for JWT/OIDC authentication
type OIDC struct {
	id, accountId      string
	validator          *jwt.Validator
	maxTokenAgeSeconds int64
	client             urlGenerator
}

// NewOIDC creates a new OIDC authentication scheme
func NewOIDC(client urlGenerator, id, accountId string, cfg OIDCConfig) *OIDC {
	return &OIDC{
		id:        id,
		accountId: accountId,
		validator: jwt.NewValidator(
			cfg.Issuer,
			cfg.Audiences,
			cfg.KeysLocation,
			true,
		),
		maxTokenAgeSeconds: cfg.MaxTokenAgeSeconds,
		client:             client,
	}
}

func (*OIDC) Type() Method {
	return MethodOIDC
}

func (o *OIDC) Authenticate(r *http.Request) (string, string) {
	if token := r.URL.Query().Get("access_token"); token != "" {
		if userID := o.validateToken(r.Context(), token); userID != "" {
			return userID, ""
		}
	}

	redirectURL := &url.URL{
		Scheme: "https",
		Host:   r.Host,
		Path:   r.URL.Path,
	}

	res, err := o.client.GetOIDCURL(r.Context(), &proto.GetOIDCURLRequest{
		Id:          o.id,
		AccountId:   o.accountId,
		RedirectUrl: redirectURL.String(),
	})
	if err != nil {
		// TODO: log
		return "", ""
	}

	return "", res.GetUrl()
}

// validateToken validates a JWT ID token and returns the user ID (subject)
// Returns empty string if token is invalid.
func (o *OIDC) validateToken(ctx context.Context, token string) string {
	if o.validator == nil {
		return ""
	}

	idToken, err := o.validator.ValidateAndParse(ctx, token)
	if err != nil {
		// TODO: log or return?
		return ""
	}

	iat, err := idToken.Claims.GetIssuedAt()
	if err != nil {
		// TODO: log or return?
		return ""
	}

	// If max token age is 0 skip this check.
	if o.maxTokenAgeSeconds > 0 && time.Since(iat.Time).Seconds() > float64(o.maxTokenAgeSeconds) {
		// TODO: log or return?
		return ""
	}

	return extractUserID(idToken)
}

func extractUserID(token *gojwt.Token) string {
	if token == nil {
		return "unknown"
	}
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return "unknown"
	}
	return getUserIDFromClaims(claims)
}

func getUserIDFromClaims(claims gojwt.MapClaims) string {
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		return userID
	}
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	return "unknown"
}
