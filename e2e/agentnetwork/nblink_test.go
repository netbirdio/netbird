//go:build e2e

package agentnetwork

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// nblinkSecondPort serves a second forward to the same endpoint from the
	// same process, so one login is shown to serve more than one listener.
	nblinkSecondPort = 8081
	// nblinkDeadPort forwards to a name nothing in the overlay serves.
	nblinkDeadPort = 8082
	// nblinkDeadUpstream is under the overlay's own domain, so the lookup is
	// answered by the in-process resolver rather than by anything outside.
	nblinkDeadUpstream = "https://nothing-serves-this.netbird.local"

	// nblinkUnreachableBody is what the forwarder itself answers when the dial
	// over the overlay fails.
	nblinkUnreachableBody = "upstream unreachable over the overlay"
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
//
// One forwarder carries most of the cases, because each one costs a session:
// it serves three forwards, reads its setup key from a file, and keeps its
// identity on a volume so the last case can restart it.
func TestNBLinkReachesAgentNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
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

	stateVolume := fmt.Sprintf("e2e-nblink-state-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = harness.RemoveDockerVolume(context.Background(), stateVolume) })

	// The upstream is the endpoint itself, over HTTPS. nblink verifies the
	// certificate like any Go client, so it needs the proxy's self-signed cert
	// — the curl helpers elsewhere in this suite sidestep that with -k.
	forward := nblinkForward(harness.NBLinkPort, "https://"+settings.Endpoint)
	nbOpts := []harness.NBLinkOption{
		harness.WithNBLinkForwards(
			nblinkForward(nblinkSecondPort, "https://"+settings.Endpoint),
			nblinkForward(nblinkDeadPort, nblinkDeadUpstream),
		),
		harness.WithNBLinkSetupKeyFile(),
		harness.WithNBLinkStateVolume(stateVolume),
	}
	nb, err := harness.StartNBLink(ctx, srv, allowedKey, forward, px.CACertPath(), nbOpts...)
	require.NoError(t, err, "start nblink")
	// nb is replaced by the restart case, so the cleanup reads the variable
	// rather than the first value.
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

	var peer api.Peer
	t.Run("the peer registers under its hostname", func(t *testing.T) {
		peers := peersWithHostname(ctx, t, nb.Hostname())
		require.Len(t, peers, 1, "exactly one peer must carry the forwarder's hostname %q", nb.Hostname())
		peer = peers[0]
		assert.True(t, peerInGroup(peer, allowed.Id),
			"the setup key read from the file must have joined the peer to its auto-group")
	})

	t.Run("the request is attributed to the forwarder's own peer", func(t *testing.T) {
		require.NotEmpty(t, peer.Ip, "the peer lookup must have run first")

		var row *api.AgentNetworkAccessLog
		require.Eventually(t, func() bool {
			logs, lerr := srv.ListAccessLogs(ctx)
			if lerr != nil || logs.TotalRecords <= before.TotalRecords {
				return false
			}
			for i, r := range logs.Data {
				if r.SessionId != nil && *r.SessionId == sessionID {
					row = &logs.Data[i]
					return true
				}
			}
			return false
		}, 30*time.Second, 2*time.Second,
			"session %q must reach the access log; a forward is not a way around accounting%s", sessionID, diag())
		require.NotNil(t, row.SourceIp, "the access log row must carry the caller's overlay address")
		assert.Equal(t, peer.Ip, *row.SourceIp,
			"the access log must name the forwarder's peer as the caller")

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

	t.Run("every forward in one process serves over the same session", func(t *testing.T) {
		scode, sbody, serr := nb.PostOn(ctx, nblinkSecondPort, harness.ChatPath,
			harness.ChatBody(harness.VLLMModel, "Reply with exactly: pong"), nil)
		require.NoError(t, serr, "the probe must reach the second listener")
		assert.Equal(t, 200, scode, "the second forward must be served too; body: %s%s", sbody, diag())
		assert.Contains(t, sbody, "chat.completion", "the second forward must carry the upstream completion back")
	})

	t.Run("an upstream nothing serves answers 502 without hanging", func(t *testing.T) {
		start := time.Now()
		dcode, dbody, derr := nb.PostOn(ctx, nblinkDeadPort, harness.ChatPath,
			harness.ChatBody(harness.VLLMModel, "Reply with exactly: pong"), nil)
		elapsed := time.Since(start)
		require.NoError(t, derr, "the probe must reach the third listener")
		assert.Equal(t, 502, dcode, "a forward whose upstream cannot be dialled must answer 502; body: %s", dbody)
		assert.Contains(t, dbody, nblinkUnreachableBody, "the 502 must be the forwarder's own answer")
		// The forwarder bounds a dial at 30s; anything near curl's 90s limit
		// means a request was left hanging.
		assert.Less(t, elapsed, 40*time.Second, "an unreachable upstream must fail fast, took %s", elapsed)
	})

	t.Run("a peer no policy names cannot reach the endpoint", func(t *testing.T) {
		other, oerr := harness.StartNBLink(ctx, srv, deniedKey, forward, px.CACertPath(),
			harness.WithNBLinkName("nblink-denied"))
		require.NoError(t, oerr, "start the second forwarder")
		t.Cleanup(func() { _ = other.Terminate(context.Background()) })
		otherDiag := func() string {
			return "\n=== denied nblink logs ===\n" + other.Logs(context.Background()) +
				"\n=== proxy logs ===\n" + px.Logs(context.Background())
		}

		// Management gives the endpoint's DNS record, the proxy peer and the
		// rule allowing 443 to it only to peers in an enabled policy's source
		// groups. This peer gets none of them, so it is refused in the overlay
		// itself and the request never reaches the proxy's router. The
		// forwarder reports that as its own 502.
		//
		// Keep asking for as long as the allowed forwarder needed to be served,
		// so a 502 cannot be blamed on a tunnel that had not settled yet.
		deniedSession := "e2e-session-nblink-denied"
		deadline := time.Now().Add(60 * time.Second)
		var ocode int
		var obody string
		for time.Now().Before(deadline) {
			ocode, obody, _ = other.Chat(ctx, harness.VLLMModel, "Reply with exactly: pong", deniedSession)
			if ocode != 502 {
				break
			}
			time.Sleep(5 * time.Second)
		}
		assert.Equal(t, 502, ocode,
			"a forwarder whose peer is in no policy's source group must not get through; body: %s%s", obody, otherDiag())
		assert.Contains(t, obody, nblinkUnreachableBody,
			"the refusal must be the forwarder failing to dial, not an answer from the proxy; body: %s", obody)
		assert.NotContains(t, obody, "chat.completion", "the refusal must not carry an upstream completion")

		// The forwarder logs why the dial failed at debug level, which this
		// suite runs at. Finding the line ties the 502 to this upstream rather
		// than to some other failure inside the forwarder.
		dialFailure := fmt.Sprintf("dial %s:443 over the overlay failed", settings.Endpoint)
		logs := other.Logs(ctx)
		require.Contains(t, logs, dialFailure, "the 502 must come from the overlay dial; logs:\n%s", logs)
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, dialFailure) {
				t.Logf("denied forwarder: %s", strings.TrimSpace(line))
				break
			}
		}

		// The allowed forwarder is still served at the same moment, so the
		// refusal is about this peer and not about the endpoint being down.
		acode, abody := chatUntil(ctx, t, nb, 200, 30*time.Second, "")
		assert.Equal(t, 200, acode, "the allowed forwarder must still be served; body: %s", abody)

		rows, lerr := srv.ListAccessLogs(ctx)
		require.NoError(t, lerr, "list access logs")
		for _, r := range rows.Data {
			assert.False(t, r.SessionId != nil && *r.SessionId == deniedSession,
				"a request that never reached the proxy must leave no access log row")
		}
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

	// Last, because it replaces the forwarder every case above used.
	t.Run("a state dir keeps the same peer across restarts", func(t *testing.T) {
		require.NotEmpty(t, peer.Id, "the peer lookup must have run first")
		require.NoError(t, nb.Terminate(ctx), "stop the first forwarder")

		restarted, rerr := harness.StartNBLink(ctx, srv, allowedKey, forward, px.CACertPath(), nbOpts...)
		require.NoError(t, rerr, "start the forwarder again on the same volume")
		nb = restarted

		peers := peersWithHostname(ctx, t, nb.Hostname())
		require.Len(t, peers, 1,
			"a restart on the same state dir must not register a second peer; got %d", len(peers))
		assert.Equal(t, peer.Id, peers[0].Id, "the restarted forwarder must come back as the same peer")

		rcode, rbody := chatUntil(ctx, t, nb, 200, 120*time.Second, "")
		assert.Equal(t, 200, rcode, "the restarted forwarder must be served again; body: %s%s", rbody, diag())
	})
}

// TestNBLinkCheck runs the image with --check, which must validate the
// configuration and print it without starting a session. The container has no
// network, so a run that tried to reach management could not exit 0.
func TestNBLinkCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	setupKey := "11111111-2222-3333-4444-555555555555"

	t.Run("a valid configuration prints its forwards and exits 0", func(t *testing.T) {
		res, err := harness.RunNBLinkCheck(ctx, map[string]string{
			"NB_MANAGEMENT_URL": "https://management.invalid",
			"NB_SETUP_KEY":      setupKey,
			"NB_FORWARD":        "http://8080=https://one.netbird.cloud,http://127.0.0.1:0=http://two.netbird.cloud:8000/v1",
		})
		require.NoError(t, err, "run the check")
		require.Equal(t, 0, res.ExitCode, "a valid configuration must pass; stderr: %s", res.Stderr)
		assert.Contains(t, res.Stdout, "forwards: 2", "both comma-separated forwards must be parsed")
		assert.Contains(t, res.Stdout, "127.0.0.1:8080 -> https://one.netbird.cloud",
			"a port-only spec must bind loopback")
		assert.Contains(t, res.Stdout, "127.0.0.1:0 -> http://two.netbird.cloud:8000/v1",
			"the second forward must be printed as given")
		assert.Contains(t, res.Stdout, "setup-key: true", "the check must report that a key is set")
		assert.NotContains(t, res.Stdout+res.Stderr, setupKey, "the check must never print the key itself")
		assert.NotContains(t, res.Stderr, "connecting to", "the check must not start a session")
	})

	t.Run("an unsupported forward exits non-zero and prints nothing", func(t *testing.T) {
		res, err := harness.RunNBLinkCheck(ctx, map[string]string{
			"NB_SETUP_KEY": setupKey,
			"NB_FORWARD":   "http://8080=https://one.netbird.cloud,tcp://5432=db.netbird.cloud:5432",
		})
		require.NoError(t, err, "run the check")
		assert.NotEqual(t, 0, res.ExitCode, "a bad spec must fail the check")
		assert.Empty(t, strings.TrimSpace(res.Stdout), "a failed check must not print a configuration")
		assert.Contains(t, res.Stderr, "tcp forwarding is not supported yet",
			"the error must name the spec that failed")
	})

	t.Run("a public bind without the opt-in exits non-zero", func(t *testing.T) {
		res, err := harness.RunNBLinkCheck(ctx, map[string]string{
			"NB_FORWARD": "http://0.0.0.0:8080=https://one.netbird.cloud",
		})
		require.NoError(t, err, "run the check")
		assert.NotEqual(t, 0, res.ExitCode, "binding beyond loopback must need --allow-public-bind")
		assert.Contains(t, res.Stderr, "NB_ALLOW_PUBLIC_BIND", "the error must say how to opt in")
	})
}

// nblinkForward builds a forward spec: a loopback listener on port, proxying
// to upstream over the overlay.
//
// The listener stays on loopback, so --allow-public-bind is never passed and
// the default an operator gets is what the suite exercises.
func nblinkForward(port int, upstream string) string {
	return fmt.Sprintf("http://127.0.0.1:%d=%s", port, upstream)
}

// peersWithHostname returns every peer registered under hostname.
func peersWithHostname(ctx context.Context, t *testing.T, hostname string) []api.Peer {
	t.Helper()

	peers, err := srv.API().Peers.List(ctx)
	require.NoError(t, err, "list peers")
	var matched []api.Peer
	for _, p := range peers {
		if p.Hostname == hostname {
			matched = append(matched, p)
		}
	}
	return matched
}

func peerInGroup(p api.Peer, groupID string) bool {
	for _, g := range p.Groups {
		if g.Id == groupID {
			return true
		}
	}
	return false
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
