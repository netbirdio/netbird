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

// The provider form used to accept anything and find out later. A typo in the
// upstream URL, a key pasted with a character missing, an AWS access key in a
// field that wants a Bedrock API key — all saved cleanly, and surfaced as a
// failed request or an empty model picker some minutes later, with nothing
// pointing back at the record that caused it.
//
// checkProviderCredential closes that gap by spending the credential once, at
// save time, against the vendor's own model listing.

// ModelLister is the vendor-facing half of the credential check.
// modeldiscovery.Client is the only production implementation; it is an
// interface because the check runs on a write path, so without a seam every
// test that saves a provider would reach a vendor over the network to do it.
type ModelLister interface {
	Fetch(ctx context.Context, req modeldiscovery.Request) ([]modeldiscovery.Model, error)
}

// checkProviderCredential asks the vendor whether this record's upstream and
// credential actually work, and refuses the write if they do not.
//
// Deliberately reuses the discovery Fetch rather than a lighter status probe:
// it exercises the exact path the model picker will take, so a URL that
// answers 200 with a login page fails here instead of passing a status check
// and producing an empty picker later.
//
// A provider the check cannot cover is saved, not blocked. That covers the
// eleven catalog entries with no listing endpoint, a Bedrock record whose
// upstream is proxied so no control-plane host can be derived, and a
// self-hosted endpoint on a private network that the proxy reaches through
// the tunnel but management cannot reach at all. None of those are evidence
// the record is wrong.
func (m *managerImpl) checkProviderCredential(ctx context.Context, provider *types.Provider) error {
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

	// The operator's message carries no status code, so the number lives here
	// or nowhere. WriteError logs whatever we return, which is the message
	// alone, so a support question about a 403 has nothing to go on without
	// this line.
	log.WithContext(ctx).Infof("agent network provider %s failed its credential check: %v", provider.ProviderID, err)

	return status.Errorf(status.InvalidArgument, "%s", message)
}

// credentialCheckFailure renders a discovery failure as the sentence the
// provider form shows, and reports whether it should block the write.
//
// The strings are written to survive WriteError lowercasing them, and they
// never echo the operator's URL: paths are case-sensitive, so an echoed URL
// would come back altered and describe something they did not type.
func credentialCheckFailure(err error) (message string, blocking bool) {
	// Not checkable. The record may be perfectly good; we simply have no way
	// to ask, so saying nothing is more honest than reporting a failure.
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
			// Everything else the vendor chose to answer with, 5xx and 429
			// included. A vendor outage blocks the write: working around it is
			// not this check's job, and saving a record we could not verify
			// would put the operator back where they started.
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

	// Anything left is ours, not theirs — a malformed request this code built,
	// or a catalog entry that does not match its parser. Blocking is still
	// right: we did not verify the record, and a save that silently skipped
	// its check is the thing this feature exists to prevent.
	return "the provider could not be checked", true
}
