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

	"github.com/netbirdio/netbird/client/proto"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testAddressResolver map[string][]string

func (r testAddressResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	fqdns, ok := r[addr]
	if !ok {
		return nil, errors.New("no such host")
	}
	return fqdns, nil
}

func TestGetKubernetesClustersSkipsPeersWithoutPTRRecords(t *testing.T) {
	t.Parallel()

	peers := []*proto.PeerState{
		{IP: "not-an-ip"},
		{IP: "100.96.6.73"},
		{IP: "::ffff:100.96.72.123"},
	}
	resolver := testAddressResolver{
		"100.96.72.123": {"regular-peer.netbird.selfhosted."},
	}

	kcs, err := getKubernetesClustersWithResolver(t.Context(), peers, "", resolver)
	assert.NoError(t, err, "discovery should continue when peers have invalid IPs or missing PTR records")
	assert.Empty(t, kcs, "discovery should ignore peers without Kubernetes proxy DNS names")
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
