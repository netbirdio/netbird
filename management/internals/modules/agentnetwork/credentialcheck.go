package agentnetwork

import (
	"context"
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/modeldiscovery"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ModelLister is the vendor-facing half of the credential check.
// modeldiscovery.Client is the only production implementation; it is an
// interface because the check runs on a write path, so without a seam every
// test that saves a provider would reach a vendor to do it.
type ModelLister interface {
	Fetch(ctx context.Context, req modeldiscovery.Request) ([]modeldiscovery.Model, error)
}

// checkProviderCredential refuses a record whose upstream or credential the
// vendor will not accept.
//
// It reuses the discovery Fetch rather than a lighter status probe so it
// exercises the path the model picker takes: a URL answering 200 with a login
// page fails here instead of producing an empty picker later.
func (m *managerImpl) checkProviderCredential(ctx context.Context, provider *types.Provider) error {
	// A record that asks the proxy to skip certificate verification is one this
	// check cannot speak for. Discovery verifies certificates, so a self-hosted
	// endpoint behind a self-signed one would be refused for a reason the
	// operator already told us to ignore — a lockout of exactly the setup the
	// flag exists for. Sending the credential over a connection management
	// declines to verify is the other way out, and a worse one.
	if provider.SkipTLSVerification {
		log.WithContext(ctx).Debugf("agent network provider %s not credential-checked: tls verification is disabled for it", provider.ProviderID)
		return nil
	}

	_, err := m.modelDiscovery.Fetch(ctx, modeldiscovery.Request{
		CatalogID:   provider.ProviderID,
		UpstreamURL: provider.UpstreamURL,
		APIKey:      provider.APIKey,
	})
	if err == nil {
		return nil
	}

	message, blocking := credentialCheckFailure(err)
	if !blocking {
		log.WithContext(ctx).Debugf("agent network provider %s not credential-checked: %v", provider.ProviderID, err)
		return nil
	}

	// WriteError logs only what we return, and that carries no status code,
	// so the vendor's number is recorded here or nowhere.
	log.WithContext(ctx).Infof("agent network provider %s failed its credential check: %v", provider.ProviderID, err)

	return status.Errorf(status.InvalidArgument, "%s", message)
}

// discoveryFailure renders a failed model listing for the operator who pressed
// the button. Every outcome here is something they did or configured — a key
// the vendor refused, an upstream that does not answer — so it owes them the
// same sentence a refused save gives, not the generic 500 an unclassified
// error turns into.
//
// ErrNoDiscovery and ErrInvalidRequest pass through untouched: the handler
// already maps them, and "this provider has no listing endpoint" is a fact
// about the catalog rather than a failure to report as one.
func discoveryFailure(ctx context.Context, catalogID string, err error) error {
	if errors.Is(err, modeldiscovery.ErrNoDiscovery) || errors.Is(err, modeldiscovery.ErrInvalidRequest) {
		return err
	}

	message, _ := credentialCheckFailure(err)
	if message == "" {
		return err
	}

	// The operator's message carries no status code, so the vendor's number is
	// recorded here or nowhere.
	log.WithContext(ctx).Infof("agent network model discovery for %s failed: %v", catalogID, err)

	return status.Errorf(status.InvalidArgument, "%s", message)
}

// credentialCheckFailure renders a discovery failure as the sentence the
// provider form shows, and reports whether it should block the write.
//
// The strings survive WriteError lowercasing them, and never echo the
// operator's URL: paths are case-sensitive, so an echoed URL comes back
// altered and describes something they did not type.
func credentialCheckFailure(err error) (message string, blocking bool) {
	// Not checkable. The record may be perfectly good and we have no way to
	// ask, so reporting a failure would be a guess.
	switch {
	case errors.Is(err, modeldiscovery.ErrNoDiscovery),
		errors.Is(err, modeldiscovery.ErrNoDiscoveryHost),
		errors.Is(err, modeldiscovery.ErrPrivateHost):
		return "", false
	}

	var vendor *modeldiscovery.VendorStatusError
	if errors.As(err, &vendor) {
		switch vendor.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "the provider rejected the credential", true
		case http.StatusNotFound, http.StatusMethodNotAllowed:
			return "the upstream url did not answer a model listing", true
		default:
			// 5xx and 429 included: an outage still leaves the record
			// unverified, which is what this refuses to save.
			return "the provider returned an error", true
		}
	}

	var unreachable *modeldiscovery.UnreachableError
	if errors.As(err, &unreachable) {
		if reason := unreachable.Reason(); reason != "" {
			return "the upstream url could not be reached: " + reason, true
		}
		return "the upstream url could not be reached", true
	}

	if errors.Is(err, modeldiscovery.ErrUnparseableListing) {
		return "the upstream url answered, but not with a model listing", true
	}

	// Ours rather than the vendor's — a request this code built badly, or a
	// catalog entry that does not match its parser. Still unverified, so it
	// still blocks.
	return "the provider could not be checked", true
}
