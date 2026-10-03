//go:build e2e

package agentnetwork

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestNBLinkReachesAgentNetwork proves an agent-network endpoint can be
// consumed from a process that has no privileges at all:
//
//	curl --> nblink (loopback, userspace peer) --tunnel--> proxy --http--> vllm
//
// The regular agent needs NET_ADMIN and a TUN device to put the endpoint on
// the network. nblink runs the same client in netstack mode and hands the
// endpoint to whatever can reach a loopback port, so the container is granted
// no capabilities and mounts no device — the whole point of the binary, and
// what fails first if netstack mode regresses.
//
// Three things are being proved together, and none of them holds on its own:
//
//   - The forward reaches the endpoint, which means the endpoint's name
//     resolved inside the process. Nothing on the container can resolve it:
//     the synthesized zone is served by the in-process DNS, /etc/resolv.conf
//     is never touched, and a name that leaked to the host resolver would be
//     NXDOMAIN.
//   - The forwarder's peer is a peer like any other. Its request is authorized
//     against the policy that names its group, metered, and written to the
//     access log under its own identity.
//   - The loopback listener still refuses what a browser can aim at it, which
//     is the one new attack surface a forward on localhost creates.
func TestNBLinkReachesAgentNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock vLLM server")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	// allowed holds the forwarder's peer and is named by the policy. denied
	// holds a second forwarder's peer and is named by nothing, so the proxy
	// has no policy to authorize it under.
	allowed, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-nblink-allowed"})
	require.NoError(t, err, "create allowed group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), allowed.Id) })

	denied, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-nblink-denied"})
	require.NoError(t, err, "create denied group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), denied.Id) })

	allowedKey := mintSetupKey(ctx, t, "e2e-nblink-allowed-key", allowed.Id)
	deniedKey := mintSetupKey(ctx, t, "e2e-nblink-denied-key", denied.Id)

	dummyKey := "sk-nblink-e2e"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "nblink-vllm",
		ProviderId:  "vllm",
		UpstreamUrl: vllm.URL,
		ApiKey:      &dummyKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: harness.VLLMModel, InputPer1k: 0.001, OutputPer1k: 0.002},
		},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	// Caps far above what this test drives, so the limit never blocks but
	// usage metering is switched on — that is what writes consumption rows.
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-nblink-allow",
		Enabled:                ptr(true),
		SourceGroups:           []string{allowed.Id},
		DestinationProviderIds: []string{prov.Id},
		Limits: &api.AgentNetworkPolicyLimits{
			TokenLimit: api.AgentNetworkPolicyTokenLimit{
				Enabled:       true,
				GroupCap:      10_000_000,
				UserCap:       10_000_000,
				WindowSeconds: 60,
			},
		},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-nblink-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	// The upstream is the endpoint itself, over HTTPS. nblink verifies the
	// certificate like any Go client, so it needs the proxy's self-signed cert
	// — the curl helpers elsewhere in this suite sidestep that with -k.
	forward := nblinkForward(settings.Endpoint)
	nb, err := harness.StartNBLink(ctx, srv, allowedKey, forward, px.CACertPath())
	require.NoError(t, err, "start nblink")
	t.Cleanup(func() { _ = nb.Terminate(context.Background()) })

	diag := func() string {
		return "\n=== nblink logs ===\n" + nb.Logs(context.Background()) +
			"\n=== proxy logs ===\n" + px.Logs(context.Background())
	}

	before, _ := srv.ListAccessLogs(ctx)
	sessionID := "e2e-session-nblink"

	// Retry to absorb the beat between the session coming up and the proxy
	// peer being reachable; the forward itself is already bound by now.
	code, body := chatUntil(ctx, t, nb, 200, 120*time.Second, sessionID)
	require.Equal(t, 200, code,
		"a chat through the nblink forward must be served; body: %s%s", body, diag())
	require.Contains(t, body, "chat.completion",
		"the body should be the upstream's OpenAI-compatible completion; got: %s", body)

	t.Run("the request is attributed to the forwarder's own peer", func(t *testing.T) {
		require.Eventually(t, func() bool {
			logs, lerr := srv.ListAccessLogs(ctx)
			if lerr != nil || logs.TotalRecords <= before.TotalRecords {
				return false
			}
			for _, r := range logs.Data {
				if r.SessionId != nil && *r.SessionId == sessionID {
					return true
				}
			}
			return false
		}, 30*time.Second, 2*time.Second,
			"session %q must reach the access log; a forward is not a way around accounting%s", sessionID, diag())

		require.Eventually(t, func() bool {
			rows, lerr := srv.ListConsumption(ctx)
			if lerr != nil {
				return false
			}
			for _, r := range rows {
				if r.TokensInput > 0 && r.TokensOutput > 0 {
					return true
				}
			}
			return false
		}, 60*time.Second, 3*time.Second, "the upstream's usage must be metered into a consumption row")
	})

	t.Run("a peer no policy names is refused", func(t *testing.T) {
		other, oerr := harness.StartNBLink(ctx, srv, deniedKey, forward, px.CACertPath(),
			harness.WithNBLinkName("nblink-denied"))
		require.NoError(t, oerr, "start the second forwarder")
		t.Cleanup(func() { _ = other.Terminate(context.Background()) })

		// The forward binds and the session comes up either way: authorization
		// happens at the proxy, on the peer's identity, not at the listener.
		// Poll for the refusal rather than asserting the first answer, which
		// can still be a 502 while the tunnel settles.
		var ocode int
		var obody string
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			ocode, obody, _ = other.Chat(ctx, harness.VLLMModel, "Reply with exactly: pong", "e2e-session-nblink-denied")
			if ocode == 403 {
				break
			}
			time.Sleep(3 * time.Second)
		}
		assert.Equal(t, 403, ocode,
			"a forwarder whose peer is in no policy's source group must be refused, not served; body: %s%s",
			obody, diag())
		// The specific deny code matters: a generic 403 would also be the
		// answer if the tunnel never came up, and that would pass this test
		// while proving nothing about authorization.
		assert.Contains(t, obody, "llm_policy.no_authorised_provider",
			"the refusal must come from the router finding no route this peer's groups authorize; body: %s", obody)
		assert.NotContains(t, obody, "chat.completion", "the refusal must not carry an upstream completion")
	})

	t.Run("the loopback listener refuses browser-driven callers", func(t *testing.T) {
		// A page the user visits can aim a request at a loopback listener in
		// several shapes. Each must be refused before anything is proxied
		// under the peer's identity, while an ordinary local caller is
		// unaffected.
		cases := []struct {
			name    string
			headers []string
			want    int
		}{
			{
				name:    "a foreign Host, which is DNS rebinding",
				headers: []string{"Host: attacker.example"},
				want:    421,
			},
			{
				name:    "a cross-origin fetch",
				headers: []string{"Origin: https://attacker.example"},
				want:    403,
			},
			{
				name: "a page on another local port, which is cross-origin too",
				// Same machine, different origin: localhost:3000 has no more
				// claim on this listener than any other site.
				headers: []string{"Origin: http://localhost:3000"},
				want:    403,
			},
			{
				name: "an embedded no-cors GET, which carries no Origin at all",
				// The shape the Host and Origin checks both miss: a loopback
				// Host and no Origin. Sec-Fetch-Site is the only signal left.
				headers: []string{"Sec-Fetch-Site: cross-site"},
				want:    403,
			},
		}
		// Every case sends the request already proven to return 200, so the
		// only difference between a refusal and a success is the header under
		// test.
		body := harness.ChatBody(harness.VLLMModel, "Reply with exactly: pong")
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				gcode, gbody, gerr := nb.Post(ctx, harness.ChatPath, body, tc.headers)
				require.NoError(t, gerr, "the probe itself must reach the listener")
				assert.Equal(t, tc.want, gcode,
					"%s must be refused by the listener, not proxied; body: %s", tc.name, gbody)
				assert.NotContains(t, gbody, "chat.completion",
					"a refused request must never carry an upstream completion back")
			})
		}

		// The control: the same request with none of those headers is served,
		// so the cases above prove a guard rather than a broken forward.
		gcode, gbody, gerr := nb.Post(ctx, harness.ChatPath, body, nil)
		require.NoError(t, gerr)
		assert.Equal(t, 200, gcode,
			"a plain local caller must still be served; body: %s%s", gbody, diag())
	})
}

// nblinkForward builds the forward spec under test: a loopback listener on the
// suite's port, proxying to the agent-network endpoint over HTTPS.
//
// The listener stays on loopback, so --allow-public-bind is never passed and
// the default an operator gets is what the suite exercises.
func nblinkForward(endpoint string) string {
	return fmt.Sprintf("http://127.0.0.1:%d=https://%s", harness.NBLinkPort, endpoint)
}

// mintSetupKey creates a reusable setup key that auto-joins its peer to one
// group, which is how a forwarder's peer lands in (or out of) a policy's
// source groups.
func mintSetupKey(ctx context.Context, t *testing.T, name, groupID string) string {
	t.Helper()

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       name,
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{groupID},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key %s", name)
	require.NotEmpty(t, sk.Key, "setup key plaintext")
	return sk.Key
}

// chatUntil retries a chat through the forwarder until it answers with want,
// returning the last status and body either way.
func chatUntil(ctx context.Context, t *testing.T, nb *harness.NBLink, want int, timeout time.Duration, sessionID string) (int, string) {
	t.Helper()

	var code int
	var body string
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, b, err := nb.Chat(ctx, harness.VLLMModel, "Reply with exactly: pong", sessionID)
		if err == nil {
			code, body = c, b
			if code == want {
				return code, body
			}
		}
		if !waitBeforeRetry(ctx, 5*time.Second) {
			break
		}
	}
	return code, body
}
