package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

type reverseResolverFunc func(context.Context, string) ([]string, error)

// LookupAddr resolves an IP address with the test resolver function.
func (f reverseResolverFunc) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return f(ctx, ip)
}

// TestGetKubernetesClustersSkipsReverseLookupFailures verifies discovery continues after a failed lookup.
func TestGetKubernetesClustersSkipsReverseLookupFailures(t *testing.T) {
	peers := []*proto.PeerState{
		{IP: "100.64.0.10"},
		{IP: "100.64.0.11"},
	}
	var lookupIPs []string
	resolver := reverseResolverFunc(func(_ context.Context, ip string) ([]string, error) {
		lookupIPs = append(lookupIPs, ip)
		if ip == peers[0].IP {
			return nil, errors.New("no PTR record")
		}
		return []string{"unrelated.example.com."}, nil
	})

	clusters, err := getKubernetesClustersWithResolver(
		t.Context(), peers, "", resolver, http.DefaultClient)
	require.NoError(t, err)
	require.Equal(t, []string{peers[0].IP, peers[1].IP}, lookupIPs,
		"discovery must process every peer after a reverse lookup failure")
	require.Empty(t, clusters, "an unrelated peer lookup failure must not abort discovery")
}

// TestPeerFQDNsUsesStoredFQDN verifies daemon-provided names avoid reverse DNS.
func TestPeerFQDNsUsesStoredFQDN(t *testing.T) {
	resolver := reverseResolverFunc(func(context.Context, string) ([]string, error) {
		t.Fatal("reverse DNS should not be called when the peer FQDN is available")
		return nil, nil
	})

	fqdns, err := peerFQDNs(t.Context(), &proto.PeerState{Fqdn: "cluster.netbird-kubeapi-proxy"}, resolver)
	require.NoError(t, err)
	require.Equal(t, []string{"cluster.netbird-kubeapi-proxy"}, fqdns)
}

// TestPeerFQDNsPreservesContextCancellation verifies cancellation is returned to the caller.
func TestPeerFQDNsPreservesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	resolver := reverseResolverFunc(func(ctx context.Context, _ string) ([]string, error) {
		return nil, ctx.Err()
	})

	_, err := peerFQDNs(ctx, &proto.PeerState{IP: "100.64.0.10"}, resolver)
	require.ErrorIs(t, err, context.Canceled)
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
