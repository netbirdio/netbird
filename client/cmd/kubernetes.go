package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

const (
	KubernetesDNSSuffix = "netbird-kubeapi-proxy"
)

var kubernetesCmd = &cobra.Command{
	Use:   "kubernetes",
	Short: "Kubernetes cluster commands.",
	Long:  "Kubernetes cluster commands.",
}

var kubernetesListCmd = &cobra.Command{
	Use:   "list",
	RunE:  kubernetesList,
	Short: "List Kubernetes clusters.",
	Long:  "List Kubernetes clusters by discovering NetBird peers running netbird-kubeapi-proxy.",
}

var kubernetesWriteKubeconfigCmd = &cobra.Command{
	Use:   "write-kubeconfig",
	RunE:  kubernetesWriteKubeconfig,
	Args:  cobra.ExactArgs(1),
	Short: "Write kubeconfig for a Kubernetes cluster.",
	Long:  "Updates kubeconfig in place to allow token-less access to the Kubernetes cluster through NetBird.",
}

func init() {
	kubernetesWriteKubeconfigCmd.Flags().String("kubeconfig", "", "path to kubeconfig file")
}

func kubernetesList(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := proto.NewDaemonServiceClient(conn)
	statusResp, err := client.Status(cmd.Context(), &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		return err
	}

	kcs, err := getKubernetesClusters(cmd.Context(), statusResp.FullStatus.Peers, "")
	if err != nil {
		return err
	}
	if len(kcs) == 0 {
		cmd.Println("No Kubernetes clusters available.")
		return nil
	}
	cmd.Println("Available Kubernetes clusters:")
	for _, k := range kcs {
		cmd.Printf("\n  - Name: %s\n    FQDN: %s\n    Version: %s\n", k.name, k.url.Host, k.version)
	}
	return nil
}

func kubernetesWriteKubeconfig(cmd *cobra.Command, args []string) error {
	kubeconfigPath, err := resolveKubeconfigPath(cmd)
	if err != nil {
		return err
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := proto.NewDaemonServiceClient(conn)
	statusResp, err := client.Status(cmd.Context(), &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		return err
	}

	clusterName := args[0]
	kcs, err := getKubernetesClusters(cmd.Context(), statusResp.FullStatus.Peers, clusterName)
	if err != nil {
		return err
	}
	if len(kcs) == 0 {
		return fmt.Errorf("kubernetes cluster named %s not found", clusterName)
	}
	if len(kcs) > 1 {
		return fmt.Errorf("too many Kubernetes clusters returned")
	}
	err = writeKubeconfig(kubeconfigPath, kcs[0])
	if err != nil {
		return err
	}
	return nil
}

type kubernetesCluster struct {
	name    string
	url     *url.URL
	version string
}

func getKubernetesClusters(ctx context.Context, peers []*proto.PeerState, nameFilter string) ([]kubernetesCluster, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	httpClient := &http.Client{
		Transport: transport,
	}
	resolver := net.Resolver{
		// Required so both DNS records are returned.
		// https://github.com/golang/go/issues/17093
		PreferGo: true,
	}

	kcs := []kubernetesCluster{}
	attempted := map[string]struct{}{}
	for _, peer := range peers {
		fqdns, err := resolver.LookupAddr(ctx, peer.IP)
		if err != nil {
			return nil, err
		}
		for _, fqdn := range fqdns {
			if _, ok := attempted[fqdn]; ok {
				continue
			}
			attempted[fqdn] = struct{}{}
			comps := strings.Split(fqdn, ".")
			if len(comps) < 2 {
				continue
			}
			if comps[1] != KubernetesDNSSuffix {
				continue
			}
			if nameFilter != "" && nameFilter != comps[0] {
				continue
			}
			clusterURL, clusterVersion, err := fingerprintClusters(ctx, httpClient, fqdn)
			if err != nil {
				log.Debugf("could not fingerprint Kubernetes cluster %s %q", fqdn, err)
				continue
			}
			kc := kubernetesCluster{
				name:    comps[0],
				url:     clusterURL,
				version: clusterVersion,
			}
			if nameFilter != "" {
				return []kubernetesCluster{kc}, nil
			}
			kcs = append(kcs, kc)
		}
	}
	return kcs, nil
}

func fingerprintClusters(ctx context.Context, httpClient *http.Client, fqdn string) (*url.URL, string, error) {
	clusterURL, err := url.Parse("https://" + fqdn)
	if err != nil {
		return nil, "", err
	}
	versionURL, err := clusterURL.Parse("/version")
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL.String(), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("expected %d response but got %s", http.StatusOK, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	versionData := map[string]string{}
	err = json.Unmarshal(b, &versionData)
	if err != nil {
		return nil, "", err
	}
	version, ok := versionData["gitVersion"]
	if !ok {
		return nil, "", errors.New("no version found in response")
	}
	return clusterURL, version, nil
}

func resolveKubeconfigPath(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("kubeconfig") {
		path, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return "", err
		}
		return path, nil
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, ".kube", "config"), nil
}

func writeKubeconfig(kubeconfigPath string, kc kubernetesCluster) error {
	b, err := os.ReadFile(kubeconfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if cfg == nil {
		cfg = map[string]any{
			"apiVersion": "v1",
			"kind":       "Config",
		}
	}

	cfg["clusters"] = appendWithName(cfg["clusters"], map[string]any{
		"name": kc.name,
		"cluster": map[string]any{
			"server":                   kc.url.String(),
			"insecure-skip-tls-verify": true,
		},
	})
	cfg["users"] = appendWithName(cfg["users"], map[string]any{
		"name": "netbird",
		"user": map[string]any{
			"token": "none",
		},
	})
	cfg["contexts"] = appendWithName(cfg["contexts"], map[string]any{
		"name": kc.name,
		"context": map[string]any{
			"cluster":   kc.name,
			"user":      "netbird",
			"namespace": "default",
		},
	})
	cfg["current-context"] = kc.name

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(kubeconfigPath, out, 0o600); err != nil {
		return err
	}
	return nil
}

func appendWithName(data any, add map[string]any) any {
	if data == nil {
		return []any{add}
	}
	v, ok := data.([]any)
	if !ok {
		return []any{add}
	}
	i := slices.IndexFunc(v, func(item any) bool {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		return m["name"] == add["name"]
	})
	if i == -1 {
		return append(v, add)
	}
	v[i] = add
	return v
}
