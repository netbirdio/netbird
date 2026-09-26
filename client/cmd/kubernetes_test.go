package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNetBirdResolverDialsConfiguredAddress(t *testing.T) {
	t.Parallel()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err, "DNS test server should listen")

	server := &dns.Server{
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Ptr: "cluster.netbird-kubeapi-proxy.example.",
			})
			if err := w.WriteMsg(resp); err != nil {
				t.Errorf("write DNS test response: %v", err)
			}
		}),
	}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Errorf("serve DNS test requests: %v", err)
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown(), "DNS test server should stop")
	})

	resolverAddress := netip.MustParseAddrPort(packetConn.LocalAddr().String())
	resolver := newNetBirdResolver(resolverAddress)
	fqdns, err := resolver.LookupAddr(t.Context(), "100.96.72.123")
	assert.NoError(t, err, "reverse lookup should use the configured NetBird resolver")
	assert.Equal(t, []string{"cluster.netbird-kubeapi-proxy.example."}, fqdns,
		"reverse lookup should return the NetBird resolver response")
}

func TestGetKubernetesClustersResolverAddressCompatibility(t *testing.T) {
	t.Parallel()

	kcs, err := getKubernetesClusters(t.Context(), nil, "", "")
	assert.NoError(t, err, "missing resolver address from an older daemon should keep existing behavior")
	assert.Empty(t, kcs, "no peers should produce no clusters")

	_, err = getKubernetesClusters(t.Context(), nil, "", "not-an-address")
	assert.Error(t, err, "malformed daemon resolver address should be rejected")
}

type testAddressResolver struct {
	records map[string][]string
	lookups []string
	err     error
}

func (r *testAddressResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.lookups = append(r.lookups, addr)
	if r.err != nil {
		return nil, r.err
	}
	fqdns, ok := r.records[addr]
	if !ok {
		return nil, errors.New("no such host")
	}
	return fqdns, nil
}

func TestGetKubernetesClustersPropagatesLookupCancellation(t *testing.T) {
	t.Parallel()

	for _, lookupErr := range []error{context.Canceled, context.DeadlineExceeded} {
		_, err := getKubernetesClustersWithResolver(
			t.Context(),
			[]*proto.PeerState{{IP: "100.96.6.73"}},
			"",
			&testAddressResolver{err: lookupErr},
		)
		assert.ErrorIs(t, err, lookupErr, "canceled DNS lookup should stop discovery")
	}
}

func TestGetKubernetesClustersSkipsPeersWithoutPTRRecords(t *testing.T) {
	t.Parallel()

	peers := []*proto.PeerState{
		{IP: "not-an-ip"},
		{IP: "100.96.6.73"},
		{IP: "::ffff:100.96.72.123"},
	}
	resolver := &testAddressResolver{
		records: map[string][]string{
			"100.96.72.123": {"regular-peer.netbird.selfhosted."},
		},
	}

	kcs, err := getKubernetesClustersWithResolver(t.Context(), peers, "", resolver)
	assert.NoError(t, err, "discovery should continue when peers have invalid IPs or missing PTR records")
	assert.Empty(t, kcs, "discovery should ignore peers without Kubernetes proxy DNS names")
	assert.Equal(t, []string{"100.96.6.73", "100.96.72.123"}, resolver.lookups, "discovery should continue after missing PTR records and normalize IPv4-mapped IPv6 addresses")
}

func TestFingerprintClusters(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint: errcheck
		w.Write([]byte(`{"gitVersion": "foobar"}`))
	}))
	defer srv.Close()

	clusterURL, clusterVersion, err := fingerprintClusters(t.Context(), srv.Client(), srv.Listener.Addr().String())
	require.NoError(t, err)
	require.Equal(t, srv.URL, clusterURL.String())
	require.Equal(t, "foobar", clusterVersion)
}

func TestResolveKubeconfigPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("could not determine home directory: %v", err)
	}
	defaultPath := filepath.Join(home, ".kube", "config")
	path, err := resolveKubeconfigPath(&cobra.Command{})
	require.NoError(t, err)
	require.Equal(t, defaultPath, path)

	flagPath := "flag-path"
	cmd := &cobra.Command{}
	cmd.Flags().String("kubeconfig", "", "")
	err = cmd.Flags().Set("kubeconfig", flagPath)
	require.NoError(t, err)
	path, err = resolveKubeconfigPath(cmd)
	require.NoError(t, err)
	require.Equal(t, flagPath, path)

	envPath := "env-path"
	t.Setenv("KUBECONFIG", envPath)
	path, err = resolveKubeconfigPath(&cobra.Command{})
	require.NoError(t, err)
	require.Equal(t, envPath, path)
}

func TestWriteKubeconfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing string
	}{
		{
			name: "empty file",
		},
		{
			name: "existing content",
			existing: `apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://foobar.com
  name: foo
current-context: test
kind: Config
users: []
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeconfigPath := filepath.Join(t.TempDir(), "config")
			err := os.WriteFile(kubeconfigPath, []byte(tt.existing), 0o644)
			require.NoError(t, err)

			kc := kubernetesCluster{
				name: "foo",
				url:  &url.URL{Scheme: "https", Host: "example.com"},
			}
			err = writeKubeconfig(kubeconfigPath, kc)
			require.NoError(t, err)

			b, err := os.ReadFile(kubeconfigPath)
			require.NoError(t, err)
			expected := `apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://example.com
  name: foo
contexts:
- context:
    cluster: foo
    namespace: default
    user: netbird
  name: foo
current-context: foo
kind: Config
users:
- name: netbird
  user:
    token: none
`
			require.Equal(t, expected, string(b))
		})
	}

}
