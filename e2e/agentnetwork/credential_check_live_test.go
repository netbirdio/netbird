//go:build e2e

package agentnetwork

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// credentialCase is one vendor to try the save-time check against. The key is
// the real one the suite already sources; corrupting it is what produces the
// refusal, so the pair of cases differ only in the credential.
type credentialCase struct {
	name      string
	catalogID string
	upstream  string
	apiKey    string
}

// liveCredentialCases mirrors the discovery matrix's env gating so a partial
// key set still yields partial coverage. Vertex is left out: its credential is
// a service-account keyfile, and mangling one produces a client-side parse
// failure rather than the vendor refusal this is about.
func liveCredentialCases() []credentialCase {
	var cases []credentialCase

	if k := os.Getenv("OPENAI_TOKEN"); k != "" {
		cases = append(cases, credentialCase{
			name: "openai", catalogID: "openai_api",
			upstream: "https://api.openai.com", apiKey: k,
		})
	}
	if k := os.Getenv("ANTHROPIC_TOKEN"); k != "" {
		cases = append(cases, credentialCase{
			name: "anthropic", catalogID: "anthropic_api",
			upstream: "https://api.anthropic.com", apiKey: k,
		})
	}
	if k := os.Getenv("AWS_BEARER_TOKEN_BEDROCK"); k != "" {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "eu-central-1"
		}
		cases = append(cases, credentialCase{
			name: "bedrock", catalogID: "bedrock_api",
			upstream: "https://bedrock-runtime." + region + ".amazonaws.com", apiKey: k,
		})
	}

	return cases
}

// TestLiveProviderCredentialCheck drives the save-time check against the real
// vendors. A unit test can only assert that a mocked refusal is classified;
// what it cannot show is that these vendors refuse a bad key on their listing
// endpoint at all, which is the assumption the whole feature rests on.
//
// The good-key case matters just as much as the bad one: a check that refused
// everything would pass a test asserting only the refusal, and would make the
// product unusable.
//
// The suite asserts on the vendors themselves, so it inherits their
// availability: the check blocks on 5xx and 429 by design, and a vendor outage
// or a rate limit during a run fails "a good credential saves" with a
// perfectly valid key. There is no retry here on purpose — a retry loop would
// also mask the outage classification these tests exist to prove. Re-run the
// job.
func TestLiveProviderCredentialCheck(t *testing.T) {
	cases := liveCredentialCases()
	if len(cases) == 0 {
		t.Skip("no live provider credentials in the environment; source ~/.llm-keys to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("a good credential saves", func(t *testing.T) {
				prov, err := srv.CreateProvider(ctx, credentialProviderRequest(tc, "e2e-cred-ok-"+tc.name, tc.apiKey))
				require.NoError(t, err, "the suite's own credential must pass its check")
				t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })
				require.NotEmpty(t, prov.Id)
			})

			t.Run("a rejected credential is refused", func(t *testing.T) {
				_, err := srv.CreateProvider(ctx, credentialProviderRequest(tc, "e2e-cred-bad-"+tc.name, corrupt(tc.apiKey)))
				require.Error(t, err, "a key the vendor rejects must not save")

				var apiErr *rest.APIError
				require.ErrorAs(t, err, &apiErr)
				require.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode,
					"a refused credential is the caller's problem to fix, not a server fault")
				require.Contains(t, strings.ToLower(apiErr.Message), "rejected the credential",
					"the message must name the credential rather than the url")

				// The record must be absent, not merely unusable: a provider
				// saved despite its check is the state this prevents.
				all, listErr := srv.ListProviders(ctx)
				require.NoError(t, listErr)
				for _, p := range all {
					require.NotEqual(t, "e2e-cred-bad-"+tc.name, p.Name, "a refused provider must not be stored")
				}
			})
		})
	}
}

// TestLiveProviderUrlCheck points a real credential at a host that is not the
// vendor's API. It is the half of the split a wrong key cannot exercise: the
// operator has to be told the URL is at fault while their key is fine.
//
// One vendor, deliberately. The transport classification under test happens
// before any vendor is reached, so running it per configured vendor would
// repeat the same code path and multiply the wall-clock of a suite that
// already creates real records. cases[0] is whichever vendor the environment
// supplies first.
func TestLiveProviderUrlCheck(t *testing.T) {
	cases := liveCredentialCases()
	if len(cases) == 0 {
		t.Skip("no live provider credentials in the environment; source ~/.llm-keys to run")
	}
	tc := cases[0]

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// A name that resolves nowhere. The check has to reach a verdict without
	// the vendor's help, which is the transport half of the classification.
	req := credentialProviderRequest(tc, "e2e-cred-badurl", tc.apiKey)
	req.UpstreamUrl = "https://not-a-real-vendor-host.netbird-e2e.invalid"

	_, err := srv.CreateProvider(ctx, req)
	require.Error(t, err, "an upstream that does not resolve must not save")

	var apiErr *rest.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode)
	require.Contains(t, strings.ToLower(apiErr.Message), "could not be reached",
		"the message must name the url rather than the credential")

	// An error is not the same fact as an absent record: a handler that saved
	// first and reported afterwards would satisfy everything above.
	all, listErr := srv.ListProviders(ctx)
	require.NoError(t, listErr)
	for _, p := range all {
		require.NotEqual(t, "e2e-cred-badurl", p.Name, "a refused provider must not be stored")
	}
}

// TestLiveProviderUpdateKeepsTheWorkingKey is the state the check exists to
// prevent on the update path: a rejected rotation that has already replaced
// the credential would take a working provider down.
//
// Also one vendor: the behaviour is in the manager's merge, not in any
// vendor's response, and each run creates and mutates a real provider record.
func TestLiveProviderUpdateKeepsTheWorkingKey(t *testing.T) {
	cases := liveCredentialCases()
	if len(cases) == 0 {
		t.Skip("no live provider credentials in the environment; source ~/.llm-keys to run")
	}
	tc := cases[0]

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	prov, err := srv.CreateProvider(ctx, credentialProviderRequest(tc, "e2e-cred-rotate", tc.apiKey))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	rotation := credentialProviderRequest(tc, "e2e-cred-rotate", corrupt(tc.apiKey))
	_, err = srv.UpdateProvider(ctx, prov.Id, rotation)
	require.Error(t, err, "a rotation the vendor rejects must not be stored")

	var apiErr *rest.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode)

	// The stored key is never returned by the API, so the proof that it
	// survived is that an edit which reuses it still passes its check. A
	// replaced key would fail here exactly as the rotation just did.
	//
	// The trailing slash is what makes that an actual check: an edit touching
	// neither the url, the key nor the catalog entry is stored without asking
	// the vendor anything, so a rename alone would pass whatever is on the
	// record. Only the host is read out of the upstream, so the same vendor is
	// reached — but the string differs, and the check runs.
	recheck := credentialProviderRequest(tc, "e2e-cred-rotate-renamed", "")
	recheck.UpstreamUrl = tc.upstream + "/"
	updated, err := srv.UpdateProvider(ctx, prov.Id, recheck)
	require.NoError(t, err, "the working key must still be the stored one")
	require.Equal(t, "e2e-cred-rotate-renamed", updated.Name)
}

// credentialProviderRequest builds a create/update body for a case. An empty apiKey is
// omitted rather than sent blank, which is how the form asks to keep whatever
// is already stored.
func credentialProviderRequest(tc credentialCase, name, apiKey string) api.AgentNetworkProviderRequest {
	req := api.AgentNetworkProviderRequest{
		Name:        name,
		ProviderId:  tc.catalogID,
		UpstreamUrl: tc.upstream,
		Enabled:     ptr(true),
	}
	if apiKey != "" {
		req.ApiKey = &apiKey
	}
	return req
}

// corrupt returns a key the vendor will reject while keeping the shape of the
// original. Replacing the last character rather than appending keeps any
// length or prefix validation satisfied, so the refusal comes from the vendor
// checking the secret rather than from it rejecting an obviously malformed
// one.
func corrupt(key string) string {
	if key == "" {
		return key
	}
	last := key[len(key)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	return key[:len(key)-1] + string(replacement)
}
