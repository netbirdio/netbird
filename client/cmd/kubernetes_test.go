package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
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

func TestFindKubernetesClustersSkipsFailedLookup(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"gitVersion": "v1.30.0"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	// Route every cluster FQDN to the test server, regardless of the resolved name.
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}}

	// The first peer has no DNS record in NetBird, so its reverse lookup fails.
	lookupAddr := func(_ context.Context, addr string) ([]string, error) {
		switch addr {
		case "100.64.0.1":
			return nil, &net.DNSError{Err: "no such host", Name: "1.0.64.100.in-addr.arpa.", IsNotFound: true}
		case "100.64.0.2":
			return []string{"homelab." + KubernetesDNSSuffix + ".netbird.cloud."}, nil
		}
		return nil, errors.New("unexpected address " + addr)
	}
	peers := []*proto.PeerState{{IP: "100.64.0.1"}, {IP: "100.64.0.2"}}

	for _, filter := range []string{"", "homelab"} {
		kcs, err := findKubernetesClusters(t.Context(), httpClient, lookupAddr, peers, filter)
		require.NoError(t, err)
		require.Len(t, kcs, 1, "cluster behind the failing peer must be found (filter %q)", filter)
		require.Equal(t, "homelab", kcs[0].name)
		require.Equal(t, "v1.30.0", kcs[0].version)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := findKubernetesClusters(ctx, httpClient, lookupAddr, peers, "homelab")
	require.ErrorIs(t, err, context.Canceled)

	// Cancellation during the last peer's lookup must surface instead of an empty result.
	ctx, cancel = context.WithCancel(t.Context())
	cancelOnLookup := func(ctx context.Context, _ string) ([]string, error) {
		cancel()
		return nil, ctx.Err()
	}
	_, err = findKubernetesClusters(ctx, httpClient, cancelOnLookup, peers[:1], "")
	require.ErrorIs(t, err, context.Canceled)
}

func TestFindKubernetesClustersReportsDeadResolver(t *testing.T) {
	t.Parallel()

	// No peer resolves, so the resolver itself is the likely problem and must be reported
	// instead of an empty cluster list.
	resolverErr := &net.DNSError{Err: "i/o timeout", Name: "1.0.64.100.in-addr.arpa.", IsTimeout: true}
	failAll := func(context.Context, string) ([]string, error) {
		return nil, resolverErr
	}
	peers := []*proto.PeerState{{IP: "100.64.0.1"}, {IP: "100.64.0.2"}}

	for _, filter := range []string{"", "homelab"} {
		kcs, err := findKubernetesClusters(t.Context(), http.DefaultClient, failAll, peers, filter)
		require.ErrorIs(t, err, resolverErr, "filter %q", filter)
		require.Empty(t, kcs)
	}

	// A peer that resolves to a non-cluster name proves the resolver works: no error, no clusters.
	someResolve := func(_ context.Context, addr string) ([]string, error) {
		if addr == "100.64.0.2" {
			return []string{"laptop.netbird.cloud."}, nil
		}
		return nil, resolverErr
	}
	kcs, err := findKubernetesClusters(t.Context(), http.DefaultClient, someResolve, peers, "")
	require.NoError(t, err)
	require.Empty(t, kcs)

	kcs, err = findKubernetesClusters(t.Context(), http.DefaultClient, failAll, nil, "")
	require.NoError(t, err, "an empty peer list is not a resolver failure")
	require.Empty(t, kcs)
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
