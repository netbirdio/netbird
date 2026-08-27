package agentnetwork

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/modeldiscovery"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// stubLister stands in for the vendor on the write path. It records what it
// was asked so a test can assert not only that the check ran, but that it ran
// against the right upstream and the right credential — and, for an edit that
// touches neither, that it did not run at all.
type stubLister struct {
	err      error
	requests []modeldiscovery.Request
}

func (s *stubLister) Fetch(_ context.Context, req modeldiscovery.Request) ([]modeldiscovery.Model, error) {
	s.requests = append(s.requests, req)
	if s.err != nil {
		return nil, s.err
	}
	return []modeldiscovery.Model{{ID: "a-model", PricingKnown: true}}, nil
}

func (s *stubLister) calls() int { return len(s.requests) }

func (s *stubLister) only(t *testing.T) modeldiscovery.Request {
	t.Helper()
	require.Len(t, s.requests, 1, "the vendor must be asked exactly once")
	return s.requests[0]
}

// TestCredentialCheckFailure_SeparatesTheUrlFromTheCredential is the contract
// the provider form is written against: an operator gets told which of the two
// fields they have to look at, and the message says so without a status code
// and without echoing the URL back at them.
func TestCredentialCheckFailure_SeparatesTheUrlFromTheCredential(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "401 is the credential",
			err:  &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 401},
			want: "the provider rejected the credential",
		},
		{
			name: "403 is the credential",
			err:  &modeldiscovery.VendorStatusError{Provider: "Bedrock", Status: 403},
			want: "the provider rejected the credential",
		},
		{
			// The host authenticated us fine and then said it has no such
			// endpoint, which is the URL being wrong rather than the key.
			name: "404 is the url",
			err:  &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 404},
			want: "the upstream url did not answer a model listing",
		},
		{
			name: "405 is the url",
			err:  &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 405},
			want: "the upstream url did not answer a model listing",
		},
		{
			name: "500 is the vendor",
			err:  &modeldiscovery.VendorStatusError{Provider: "Anthropic", Status: 500},
			want: "the provider returned an error",
		},
		{
			name: "503 is the vendor",
			err:  &modeldiscovery.VendorStatusError{Provider: "Anthropic", Status: 503},
			want: "the provider returned an error",
		},
		{
			name: "429 is the vendor",
			err:  &modeldiscovery.VendorStatusError{Provider: "Anthropic", Status: 429},
			want: "the provider returned an error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, blocking := credentialCheckFailure(tc.err)
			require.True(t, blocking, "a vendor refusal must block the write")
			require.Equal(t, tc.want, got)
		})
	}
}

// TestCredentialCheckFailure_NamesTheTransportFault covers the failures that
// never reached the vendor. The distinction inside them is worth keeping: a
// refused connection is a wrong port and an unknown host is a wrong hostname,
// and an operator staring at a URL they believe in needs to be told which.
func TestCredentialCheckFailure_NamesTheTransportFault(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "unknown host",
			err:  &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true},
			want: "the upstream url could not be reached: no such host",
		},
		{
			name: "dns failure that is not a missing name",
			err:  &net.DNSError{Err: "server misbehaving", Name: "api.example.com"},
			want: "the upstream url could not be reached: dns lookup failed",
		},
		{
			name: "connection refused",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
			want: "the upstream url could not be reached: connection refused",
		},
		{
			name: "host unreachable",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH},
			want: "the upstream url could not be reached: host unreachable",
		},
		{
			name: "timeout",
			err:  fmt.Errorf("dial: %w", os.ErrDeadlineExceeded),
			want: "the upstream url could not be reached: connection timed out",
		},
		{
			name: "context deadline",
			err:  fmt.Errorf("dial: %w", context.DeadlineExceeded),
			want: "the upstream url could not be reached: connection timed out",
		},
		{
			name: "untrusted certificate",
			err:  &tls.CertificateVerificationError{},
			want: "the upstream url could not be reached: tls certificate not trusted",
		},
		{
			name: "plaintext service on an https url",
			err:  tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			want: "the upstream url could not be reached: not a tls endpoint",
		},
		{
			// Nothing we recognise. Better to say only that it could not be
			// reached than to paste a Go error into the provider form.
			name: "cause we do not recognise",
			err:  errors.New("something went sideways"),
			want: "the upstream url could not be reached",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := &modeldiscovery.UnreachableError{Provider: "OpenAI", Err: tc.err}
			got, blocking := credentialCheckFailure(wrapped)
			require.True(t, blocking, "an unreachable upstream must block the write")
			require.Equal(t, tc.want, got)
		})
	}
}

// TestCredentialCheckFailure_AnAnsweringUrlThatIsNotTheApi covers the case a
// status probe would wave through: the host is up, the credential was accepted
// or not required, and the body is a login page. Reusing the discovery parser
// for the check is what catches it.
func TestCredentialCheckFailure_AnAnsweringUrlThatIsNotTheApi(t *testing.T) {
	err := fmt.Errorf("%w: decode model listing: unexpected token", modeldiscovery.ErrUnparseableListing)

	got, blocking := credentialCheckFailure(err)
	require.True(t, blocking)
	require.Equal(t, "the upstream url answered, but not with a model listing", got)
}

// TestCredentialCheckFailure_WhatCannotBeCheckedIsNotAFailure pins the
// difference between "this record is wrong" and "we have no way to ask". A
// gateway with no listing endpoint, a Bedrock record pointed at a proxy, and a
// self-hosted endpoint the proxy reaches through the tunnel are all legitimate
// providers. Blocking them would make the feature a lockout.
func TestCredentialCheckFailure_WhatCannotBeCheckedIsNotAFailure(t *testing.T) {
	cases := map[string]error{
		"no listing endpoint": modeldiscovery.ErrNoDiscovery,
		"no derivable host":   fmt.Errorf("%w: %w: bedrock", modeldiscovery.ErrInvalidRequest, modeldiscovery.ErrNoDiscoveryHost),
		"private upstream":    fmt.Errorf("%w: %w: 10.0.0.5", modeldiscovery.ErrInvalidRequest, modeldiscovery.ErrPrivateHost),
	}

	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			message, blocking := credentialCheckFailure(err)
			require.False(t, blocking, "a provider we cannot check must still save")
			require.Empty(t, message)
		})
	}
}

// TestCredentialCheckFailure_AnUnrecognisedFailureStillBlocks covers a fault of
// ours rather than the vendor's — a malformed request this code built, or a
// catalog entry whose parser does not match its endpoint. The record went
// unverified either way, and silently saving what we could not check is the
// thing this feature exists to prevent.
func TestCredentialCheckFailure_AnUnrecognisedFailureStillBlocks(t *testing.T) {
	message, blocking := credentialCheckFailure(errors.New("no parser for listing shape \"\""))
	require.True(t, blocking)
	require.Equal(t, "the provider could not be checked", message)
}

// newCheckedProvider returns a record shaped the way the handler guarantees
// one: a known catalog id, a public upstream and a key.
func newCheckedProvider(accountID string) *types.Provider {
	provider := types.NewProvider(accountID)
	provider.ProviderID = "openai_api"
	provider.Name = "openai"
	provider.UpstreamURL = "https://api.openai.com"
	provider.APIKey = "sk-good"
	provider.Enabled = true
	return provider
}

// TestCreateProvider_RefusesARecordTheVendorRejects is the whole point of the
// feature: a key with a character missing used to save cleanly and surface
// minutes later as a failed request with nothing pointing back at the record.
func TestCreateProvider_RefusesARecordTheVendorRejects(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.vendor.err = &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 401}
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	_, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "the provider rejected the credential")

	var sErr *status.Error
	require.ErrorAs(t, err, &sErr)
	require.Equal(t, status.InvalidArgument, sErr.Type(), "the refusal must reach the caller as a 422")

	stored, err := f.store.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "account1")
	require.NoError(t, err)
	require.Empty(t, stored, "a record that failed its check must not be written")
}

// TestCreateProvider_ChecksTheCredentialItWasGiven pins what the vendor is
// asked with, since a check run against the wrong upstream or a stale key
// would pass while proving nothing.
func TestCreateProvider_ChecksTheCredentialItWasGiven(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	_, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)

	asked := f.vendor.only(t)
	require.Equal(t, "openai_api", asked.CatalogID)
	require.Equal(t, "https://api.openai.com", asked.UpstreamURL)
	require.Equal(t, "sk-good", asked.APIKey)
}

// TestUpdateProvider_AUrlOnlyChangeIsCheckedAgainstTheStoredKey covers the
// case that shaped where the check sits. The key never returns to the browser,
// so an operator editing only the URL has none to offer — the stored one is
// the only credential there is, and the new URL still has to be proven with
// it.
func TestUpdateProvider_AUrlOnlyChangeIsCheckedAgainstTheStoredKey(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)
	f.vendor.requests = nil

	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Update, true)
	edit := newCheckedProvider("account1")
	edit.ID = created.ID
	edit.UpstreamURL = "https://gateway.example.com"
	edit.APIKey = "" // the form sends no key when it was not retyped

	_, err = f.manager.UpdateProvider(ctx, "user1", edit)
	require.NoError(t, err)

	asked := f.vendor.only(t)
	require.Equal(t, "https://gateway.example.com", asked.UpstreamURL, "the new url must be what gets tested")
	require.Equal(t, "sk-good", asked.APIKey, "and the stored key must be what tests it")
}

// TestUpdateProvider_AFailedRotationLeavesTheWorkingKeyInPlace is the
// half-applied state the check must never produce: refusing the new key while
// having already replaced the old one would take the provider down.
func TestUpdateProvider_AFailedRotationLeavesTheWorkingKeyInPlace(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)

	f.vendor.err = &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 403}
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Update, true)
	rotation := newCheckedProvider("account1")
	rotation.ID = created.ID
	rotation.APIKey = "sk-typo"

	_, err = f.manager.UpdateProvider(ctx, "user1", rotation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the provider rejected the credential")

	stored, err := f.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, "account1", created.ID)
	require.NoError(t, err)
	require.Equal(t, "sk-good", stored.APIKey, "the rejected key must not have replaced the working one")
}

// TestUpdateProvider_AnEditTouchingNeitherFieldAsksNoVendor keeps renames,
// model rows and price edits off the vendor's doorstep. They have nothing new
// to prove, and making them wait on a vendor — or fail because one is having a
// bad day — would be a tax on edits that carry no risk.
func TestUpdateProvider_AnEditTouchingNeitherFieldAsksNoVendor(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)
	f.vendor.requests = nil
	// Any call at all now would fail the update, which is what makes the
	// assertion below load-bearing rather than decorative.
	f.vendor.err = &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 500}

	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Update, true)
	rename := newCheckedProvider("account1")
	rename.ID = created.ID
	rename.Name = "openai-renamed"
	rename.APIKey = ""

	_, err = f.manager.UpdateProvider(ctx, "user1", rename)
	require.NoError(t, err, "an edit that changes neither url nor key must not be checked")
	require.Zero(t, f.vendor.calls(), "and must not reach the vendor at all")
}

// TestCreateProvider_AProviderWeCannotCheckStillSaves covers the eleven
// catalog entries with no listing endpoint, a Bedrock record behind a proxy,
// and a self-hosted endpoint on a private network. None of those are evidence
// the record is wrong, and refusing them would make this a lockout.
func TestCreateProvider_AProviderWeCannotCheckStillSaves(t *testing.T) {
	cases := map[string]error{
		"gateway with no listing endpoint": modeldiscovery.ErrNoDiscovery,
		"bedrock behind a proxy":           fmt.Errorf("%w: %w", modeldiscovery.ErrInvalidRequest, modeldiscovery.ErrNoDiscoveryHost),
		"self-hosted on a private network": fmt.Errorf("%w: %w", modeldiscovery.ErrInvalidRequest, modeldiscovery.ErrPrivateHost),
	}

	for name, vendorErr := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newBootstrapFixture(t)
			f.vendor.err = vendorErr
			f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

			created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
			require.NoError(t, err)
			require.NotNil(t, created)

			stored, err := f.store.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "account1")
			require.NoError(t, err)
			require.Len(t, stored, 1, "a provider we cannot check must still be written")
		})
	}
}

// TestDiscoveryFailure_TellsTheOperatorWhatWentWrong covers the button, not the
// save. Pressing "Load models from provider" against a bad key used to answer
// "internal server error", which names neither the thing that failed nor
// anything the operator could act on — every outcome here is their key or their
// URL.
func TestDiscoveryFailure_TellsTheOperatorWhatWentWrong(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"refused credential": {
			err:  &modeldiscovery.VendorStatusError{Provider: "Bedrock", Status: 403},
			want: "the provider rejected the credential",
		},
		"upstream that is not the api": {
			err:  &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 404},
			want: "the upstream url did not answer a model listing",
		},
		"upstream that does not resolve": {
			err: &modeldiscovery.UnreachableError{
				Provider: "OpenAI",
				Err:      &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true},
			},
			want: "the upstream url could not be reached: no such host",
		},
		"vendor having a bad day": {
			err:  &modeldiscovery.VendorStatusError{Provider: "Anthropic", Status: 503},
			want: "the provider returned an error",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := discoveryFailure(context.Background(), "openai_api", tc.err)
			require.EqualError(t, err, tc.want)

			var sErr *status.Error
			require.ErrorAs(t, err, &sErr)
			require.Equal(t, status.InvalidArgument, sErr.Type(),
				"a failure the operator caused must not read as a server fault")
		})
	}
}

// TestDiscoveryFailure_LeavesTheCatalogFactsAlone keeps the two outcomes the
// handler already maps. A provider with no listing endpoint is a fact about the
// catalog entry, and the caller falls back to the catalog's own models rather
// than showing an error at all — rewriting it as a refusal would turn a normal
// path into one.
func TestDiscoveryFailure_LeavesTheCatalogFactsAlone(t *testing.T) {
	for name, err := range map[string]error{
		"no listing endpoint": modeldiscovery.ErrNoDiscovery,
		"bad request":         fmt.Errorf("%w: unknown catalog provider", modeldiscovery.ErrInvalidRequest),
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, err, discoveryFailure(context.Background(), "openai_api", err),
				"the handler's own mapping must still see the original error")
		})
	}
}

// TestDiscoverProviderModels_SurfacesTheVendorRefusal drives the manager rather
// than the classifier, so a future refactor that stops translating on this path
// fails here rather than silently going back to 500s.
func TestDiscoverProviderModels_SurfacesTheVendorRefusal(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.vendor.err = &modeldiscovery.VendorStatusError{Provider: "OpenAI", Status: 401}
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	_, err := f.manager.DiscoverProviderModels(ctx, "account1", "user1", modeldiscovery.Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-wrong",
	}, "")

	require.EqualError(t, err, "the provider rejected the credential")
}

// TestDiscoverProviderModels_ListsAgainstTheUrlOnTheForm covers the edit the
// operator cannot otherwise make: the upstream has been retyped and the
// credential has not, because the API never returned it to be retyped. Naming
// the record supplies the key; the request supplies the URL under test.
func TestDiscoverProviderModels_ListsAgainstTheUrlOnTheForm(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	// Twice: the create, and the listing, which is gated on Create too.
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)
	f.vendor.requests = nil

	_, err = f.manager.DiscoverProviderModels(ctx, "account1", "user1", modeldiscovery.Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://gateway.example.com",
	}, created.ID)
	require.NoError(t, err)

	asked := f.vendor.only(t)
	require.Equal(t, "https://gateway.example.com", asked.UpstreamURL, "the typed url must be the one listed against")
	require.Equal(t, "sk-good", asked.APIKey, "and the stored key must be what lists it")
}

// TestDiscoverProviderModels_FallsBackToTheStoredUrl keeps the plain refresh
// working: a request naming only the record still reaches the saved upstream.
func TestDiscoverProviderModels_FallsBackToTheStoredUrl(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)
	stored := f.vendor.only(t).UpstreamURL
	f.vendor.requests = nil

	_, err = f.manager.DiscoverProviderModels(ctx, "account1", "user1", modeldiscovery.Request{
		CatalogID: "openai_api",
	}, created.ID)
	require.NoError(t, err)

	require.Equal(t, stored, f.vendor.only(t).UpstreamURL)
}

// TestUpdateProvider_MovingARecordToAnotherVendorIsChecked covers the edit that
// changes neither field the vendor judges and still invalidates both. The
// catalog entry decides which vendor is asked and under which auth header, so
// the unchanged credential is now being offered somewhere it has never been
// accepted.
func TestUpdateProvider_MovingARecordToAnotherVendorIsChecked(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	created, err := f.manager.CreateProvider(ctx, "user1", newCheckedProvider("account1"))
	require.NoError(t, err)
	f.vendor.requests = nil

	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Update, true)
	edit := newCheckedProvider("account1")
	edit.ID = created.ID
	edit.ProviderID = "anthropic_api"
	edit.APIKey = ""

	_, err = f.manager.UpdateProvider(ctx, "user1", edit)
	require.NoError(t, err)

	require.Equal(t, "anthropic_api", f.vendor.only(t).CatalogID,
		"the new vendor is the one that has to accept the key")
}

// TestCreateProvider_ASkipTlsRecordIsNotCheckedAgainstItsCertificate covers the
// lockout the check would otherwise be: the flag exists for a self-hosted
// endpoint behind a certificate nothing public can verify, and discovery
// verifies certificates. Refusing the save would reject the record for the one
// reason the operator already declared they accept.
func TestCreateProvider_ASkipTlsRecordIsNotCheckedAgainstItsCertificate(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.vendor.err = &modeldiscovery.UnreachableError{
		Provider: "OpenAI",
		Err:      &tls.CertificateVerificationError{},
	}
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	provider := newCheckedProvider("account1")
	provider.SkipTLSVerification = true

	created, err := f.manager.CreateProvider(ctx, "user1", provider)
	require.NoError(t, err, "a record we were told not to verify must still save")
	require.NotEmpty(t, created.ID)
	require.Zero(t, f.vendor.calls(), "and the vendor must not be asked at all")
}

// TestCreateProvider_TheStoredKeyIsTheOneThatWasChecked pins the two halves to
// one value. The vendor call trims the credential before building its auth
// header; the synthesiser substitutes the stored one verbatim. A key pasted
// with surrounding whitespace would otherwise pass its check and then fail
// every request the provider serves.
func TestCreateProvider_TheStoredKeyIsTheOneThatWasChecked(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	provider := newCheckedProvider("account1")
	provider.APIKey = "  sk-good\n"

	created, err := f.manager.CreateProvider(ctx, "user1", provider)
	require.NoError(t, err)

	require.Equal(t, "sk-good", f.vendor.only(t).APIKey, "the vendor is asked about the trimmed key")

	stored, err := f.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, "account1", created.ID)
	require.NoError(t, err)
	require.Equal(t, "sk-good", stored.APIKey, "and that is the one the proxy will send")
}

// TestUpdateProvider_TurningTlsVerificationBackOnChecksTheRecord covers the
// hole the skip-TLS exemption opens on its own. Such a record is stored without
// ever being checked, so the moment verification is switched back on is the
// first moment it can be checked at all — and none of the three fields the
// re-check usually watches has to move for that to happen.
func TestUpdateProvider_TurningTlsVerificationBackOnChecksTheRecord(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)
	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

	unchecked := newCheckedProvider("account1")
	unchecked.SkipTLSVerification = true
	created, err := f.manager.CreateProvider(ctx, "user1", unchecked)
	require.NoError(t, err)
	require.Zero(t, f.vendor.calls(), "the create was exempt")

	f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Update, true)
	edit := newCheckedProvider("account1")
	edit.ID = created.ID
	edit.APIKey = ""
	edit.SkipTLSVerification = false

	_, err = f.manager.UpdateProvider(ctx, "user1", edit)
	require.NoError(t, err)
	require.Equal(t, 1, f.vendor.calls(), "switching verification on must check what was never checked")
}
