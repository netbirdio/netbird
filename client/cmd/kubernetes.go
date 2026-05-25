package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/netbirdio/netbird/client/proto"
)

const (
	KubernetesDNSSuffix = "netbird-kubeapi-proxy"
)

var kubernetesCmd = &cobra.Command{
	Use:   "kubernetes",
	Short: "Kubernetes cluster commands",
}

var kubernetesListCmd = &cobra.Command{
	Use:  "list",
	RunE: kubernetesList,
}

var kubernetesWriteKubeconfigCmd = &cobra.Command{
	Use:  "write-kubeconfig",
	RunE: kubernetesWriteKubeconfig,
	Args: cobra.ExactArgs(1),
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

	path := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return err
	}

	clusterName := args[0]
	kcs, err := getKubernetesClusters(cmd.Context(), statusResp.FullStatus.Peers, clusterName)
	if err != nil {
		return err
	}
	if len(kcs) == 0 {
		return fmt.Errorf("Kubernetes cluster named %s not found", clusterName)
	}
	if len(kcs) > 1 {
		return fmt.Errorf("too many Kubernetes clusters returned")
	}
	kc := kcs[0]

	config.Clusters[kc.name] = &clientcmdapi.Cluster{
		InsecureSkipTLSVerify: true,
		Server:                kc.url.String(),
	}
	config.AuthInfos["netbird"] = &clientcmdapi.AuthInfo{
		Token: "none",
	}
	config.Contexts[kc.name] = &clientcmdapi.Context{
		AuthInfo:  "netbird",
		Cluster:   kc.name,
		Namespace: "default",
	}
	err = clientcmd.WriteToFile(*config, path)
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
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resolver := net.Resolver{
		// Required so both DNS records are returned.
		// https://github.com/golang/go/issues/17093
		PreferGo: true,
	}

	kcs := []kubernetesCluster{}
	attempted := map[string]any{}
	for _, peer := range peers {
		fqdns, err := resolver.LookupAddr(ctx, peer.IP)
		if err != nil {
			return nil, err
		}
		for _, fqdn := range fqdns {
			if _, ok := attempted[fqdn]; ok {
				continue
			}
			attempted[fqdn] = nil
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
			kc, err := fingerprintClusters(ctx, httpClient, comps[0], fqdn)
			if err != nil {
				return nil, err
			}
			if nameFilter != "" {
				return []kubernetesCluster{kc}, nil
			}
			kcs = append(kcs, kc)
		}
	}
	return kcs, nil
}

func fingerprintClusters(ctx context.Context, httpClient *http.Client, name, fqdn string) (kubernetesCluster, error) {
	clusterURL, err := url.Parse("https://" + fqdn)
	if err != nil {
		return kubernetesCluster{}, err
	}
	versionURL, err := clusterURL.Parse("/version")
	if err != nil {
		return kubernetesCluster{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL.String(), nil)
	if err != nil {
		return kubernetesCluster{}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return kubernetesCluster{}, err
	}
	defer io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return kubernetesCluster{}, err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return kubernetesCluster{}, err
	}
	versionData := map[string]string{}
	err = json.Unmarshal(b, &versionData)
	if err != nil {
		return kubernetesCluster{}, err
	}
	version, ok := versionData["gitVersion"]
	if !ok {
		return kubernetesCluster{}, err
	}
	kc := kubernetesCluster{
		name:    name,
		version: version,
		url:     clusterURL,
	}
	return kc, nil
}
