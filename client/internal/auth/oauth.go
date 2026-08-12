package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	mgm "github.com/netbirdio/netbird/shared/management/client"
)

// OAuthFlow represents an interface for authorization using different OAuth 2.0 flows
type OAuthFlow interface {
	RequestAuthInfo(ctx context.Context) (AuthFlowInfo, error)
	WaitToken(ctx context.Context, info AuthFlowInfo) (TokenInfo, error)
	GetClientID(ctx context.Context) string
}

// HTTPClient http client interface for API calls
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthFlowInfo holds information for the OAuth 2.0  authorization flow
type AuthFlowInfo struct { //nolint:revive
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Claims used when validating the access token
type Claims struct {
	Audience interface{} `json:"aud"`
}

// TokenInfo holds information of issued access token
type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UseIDToken   bool   `json:"-"`
	Email        string `json:"-"`
}

// GetTokenToUse returns either the access or id token based on UseIDToken field
func (t TokenInfo) GetTokenToUse() string {
	if t.UseIDToken {
		return t.IDToken
	}
	return t.AccessToken
}

// errFlowNotConfigured marks a flow this deployment does not offer: management returned no
// configuration for it, the configuration it returned is incomplete, or the IdP refuses to serve
// the grant. It is the only condition that makes the client try the other flow, so that a
// transient failure keeps failing on the flow the user actually wants.
var errFlowNotConfigured = errors.New("authorization flow is not configured")

// ssoUnavailableError reports that the management server offers no usable SSO flow at all.
// Retrying cannot help, so callers should surface it to the user instead of backing off.
type ssoUnavailableError struct {
	msg string
}

func (e *ssoUnavailableError) Error() string {
	return e.msg
}

// oauthFlowInit names one of the OAuth flows and builds it from the management configuration.
type oauthFlowInit struct {
	name string
	init func(a *Auth, client *mgm.GrpcClient, hint string) (OAuthFlow, error)
}

// authFactory hands out a management connection to build a flow with, plus the cleanup that
// releases it. Callers that own a long-lived connection return it with a no-op cleanup.
type authFactory func(ctx context.Context) (*Auth, func(), error)

// fallbackFlow wraps the flow that was picked at initialization time with the flows that were
// not tried. Whether the IdP actually serves a flow only shows up when the flow is run: an IdP
// with the device grant disabled answers the device code request with 404 even though
// management handed out a device flow configuration. When that happens the wrapper swaps in the
// next flow instead of failing the login.
type fallbackFlow struct {
	mu        sync.Mutex
	active    OAuthFlow
	remaining []oauthFlowInit
	hint      string
	newAuth   authFactory
}

func (f *fallbackFlow) RequestAuthInfo(ctx context.Context) (AuthFlowInfo, error) {
	info, err := f.current().RequestAuthInfo(ctx)
	if err == nil || !isFlowUnavailable(err) {
		return info, err
	}

	next, nextErr := f.initNext(ctx)
	if nextErr != nil {
		log.Debugf("failed to fall back to another authorization flow: %v", nextErr)
		return AuthFlowInfo{}, err
	}

	return next.RequestAuthInfo(ctx)
}

func (f *fallbackFlow) WaitToken(ctx context.Context, info AuthFlowInfo) (TokenInfo, error) {
	return f.current().WaitToken(ctx, info)
}

func (f *fallbackFlow) GetClientID(ctx context.Context) string {
	return f.current().GetClientID(ctx)
}

func (f *fallbackFlow) current() OAuthFlow {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.active
}

// initNext initializes the next flow this deployment offers and makes it the active one.
func (f *fallbackFlow) initNext(ctx context.Context) (OAuthFlow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.remaining) == 0 {
		return nil, errors.New("no authorization flow left to try")
	}

	a, cleanup, err := f.newAuth(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	flow, remaining, err := initFirstAvailableFlow(a, a.grpcClient(), f.remaining, f.hint)
	if err != nil {
		return nil, err
	}

	log.Infof("the identity provider does not serve the selected authorization flow, continuing with the next one")
	f.active = flow
	f.remaining = remaining

	return flow, nil
}

// preferDeviceFlow reports whether the device code flow should be tried before PKCE. PKCE needs
// a browser on this host and a loopback listener to receive the redirect, neither of which
// exists on a Unix host without a graphical session. The GOOS guard keeps a caller that reports
// no graphical session on a platform that always has one from changing the preference.
func preferDeviceFlow(force bool, hasGraphicalSession bool) bool {
	return force || (runtime.GOOS == "linux" || runtime.GOOS == "freebsd") && !hasGraphicalSession
}

// flowOrder returns both flows in the order they should be attempted.
func flowOrder(preferDevice bool) []oauthFlowInit {
	pkce := oauthFlowInit{name: "pkce authorization flow", init: initPKCEFlow}
	device := oauthFlowInit{name: "device code flow", init: initDeviceFlow}

	if preferDevice {
		return []oauthFlowInit{device, pkce}
	}
	return []oauthFlowInit{pkce, device}
}

func initPKCEFlow(a *Auth, client *mgm.GrpcClient, hint string) (OAuthFlow, error) {
	flow, err := a.getPKCEFlow(client)
	if err != nil {
		return nil, err
	}

	if hint != "" {
		flow.SetLoginHint(hint)
	}

	return flow, nil
}

func initDeviceFlow(a *Auth, client *mgm.GrpcClient, hint string) (OAuthFlow, error) {
	flow, err := a.getDeviceFlow(client)
	if err != nil {
		return nil, err
	}

	if hint != "" {
		flow.SetLoginHint(hint)
	}

	return flow, nil
}

// NewOAuthFlow initializes and returns an OAuth flow based on the management configuration.
//
// Both flows are optional server side: management answers NotFound for a flow it has no
// configuration for. The preferred flow is tried first and the other one is used as a fallback,
// so a server that only offers one of them still works. forceDeviceCodeFlow prefers the device
// code flow regardless of platform (e.g. for Android TV).
func NewOAuthFlow(ctx context.Context, config *profilemanager.Config, hasGraphicalSession bool, forceDeviceCodeFlow bool, hint string) (OAuthFlow, error) {
	authClient, err := NewAuth(ctx, config.PrivateKey, config.ManagementURL, config)
	if err != nil {
		return nil, fmt.Errorf("create auth client: %w", err)
	}
	defer func() {
		if err := authClient.Close(); err != nil {
			log.Debugf("failed to close auth client: %v", err)
		}
	}()

	// the connection above is closed on return, so a later fallback opens its own
	newAuth := func(ctx context.Context) (*Auth, func(), error) {
		a, err := NewAuth(ctx, config.PrivateKey, config.ManagementURL, config)
		if err != nil {
			return nil, nil, fmt.Errorf("create auth client: %w", err)
		}
		return a, func() {
			if err := a.Close(); err != nil {
				log.Debugf("failed to close auth client: %v", err)
			}
		}, nil
	}

	flows := flowOrder(preferDeviceFlow(forceDeviceCodeFlow, hasGraphicalSession))
	return oauthFlowWithFallback(authClient, authClient.grpcClient(), flows, hint, newAuth)
}

// oauthFlowWithFallback initializes the first flow this deployment offers, moving on to the next
// one when a flow is not configured here. It only fails once every flow has been tried, and any
// flow left untried is handed to the returned flow so it can still fall back if the IdP rejects
// the flow that was picked.
func oauthFlowWithFallback(a *Auth, client *mgm.GrpcClient, flows []oauthFlowInit, hint string, newAuth authFactory) (OAuthFlow, error) {
	flow, remaining, err := initFirstAvailableFlow(a, client, flows, hint)
	if err != nil {
		return nil, err
	}

	if len(remaining) == 0 {
		return flow, nil
	}

	return &fallbackFlow{
		active:    flow,
		remaining: remaining,
		hint:      hint,
		newAuth:   newAuth,
	}, nil
}

// initFirstAvailableFlow returns the first flow that could be initialized along with the flows
// after it, which are still untried.
func initFirstAvailableFlow(a *Auth, client *mgm.GrpcClient, flows []oauthFlowInit, hint string) (OAuthFlow, []oauthFlowInit, error) {
	var errs []error
	for i, f := range flows {
		flow, err := f.init(a, client, hint)
		if err == nil {
			return flow, flows[i+1:], nil
		}

		errs = append(errs, fmt.Errorf("%s: %w", f.name, err))

		// only a flow this deployment does not offer is worth replacing with another one
		if !isFlowUnavailable(err) {
			break
		}
		if i < len(flows)-1 {
			log.Infof("%s is not configured (%v), falling back to %s", f.name, err, flows[i+1].name)
		}
	}

	return nil, nil, flowInitError(a.mgmURL, errs)
}

// flowInitError turns the per-flow initialization errors into a single actionable error. The
// message stays neutral about what to do instead: SSO is also how a peer extends its session and
// authenticates SSH, where a setup key is no alternative. Callers that are enrolling a device add
// that advice themselves, see IsSSOUnavailable.
func flowInitError(mgmURL *url.URL, errs []error) error {
	if allMatch(errs, isFlowUnimplemented) {
		return &ssoUnavailableError{msg: fmt.Sprintf("the management server, %s, does not support SSO providers, "+
			"please update your server", mgmURL)}
	}

	if allMatch(errs, isFlowUnavailable) {
		return &ssoUnavailableError{msg: "the management server has no SSO provider configured: " +
			"neither the pkce authorization flow nor the device code flow is available"}
	}

	return fmt.Errorf("initialize authorization flow: %w", errors.Join(errs...))
}

// IsSSOUnavailable reports whether err means the management server offers no usable SSO flow, so
// no retry and no other flow can help. Enrollment paths use it to point the user at setup keys.
func IsSSOUnavailable(err error) bool {
	var ssoUnavailable *ssoUnavailableError
	return errors.As(err, &ssoUnavailable)
}

// WithSetupKeyAdvice appends enrollment guidance to an SSO-unavailable error and returns any
// other error unchanged. Only enrollment can fall back to a setup key: extending a session and
// authenticating SSH cannot, so those paths must not call this.
//
// The login paths that do call it cannot tell an unregistered peer from an SSO-enrolled one
// whose session expired, since both answer PermissionDenied, so the advice names the case it
// applies to rather than telling an enrolled peer to do something that cannot work.
func WithSetupKeyAdvice(err error) error {
	if !IsSSOUnavailable(err) {
		return err
	}

	return fmt.Errorf("%w. If this device is not enrolled yet, enroll it with a setup key instead: "+
		"https://docs.netbird.io/how-to/register-machines-using-setup-keys", err)
}

func allMatch(errs []error, match func(error) bool) bool {
	if len(errs) == 0 {
		return false
	}

	for _, err := range errs {
		if !match(err) {
			return false
		}
	}
	return true
}

// isFlowUnavailable reports whether the flow is not on offer here: management has no
// configuration for it (NotFound), predates the RPC entirely (Unimplemented), returned an
// incomplete configuration, or the IdP does not serve the grant.
func isFlowUnavailable(err error) bool {
	return errors.Is(err, errFlowNotConfigured) ||
		hasStatusCode(err, codes.NotFound) ||
		hasStatusCode(err, codes.Unimplemented)
}

func isFlowUnimplemented(err error) bool {
	return hasStatusCode(err, codes.Unimplemented)
}

func hasStatusCode(err error, code codes.Code) bool {
	s, ok := gstatus.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == code
}
