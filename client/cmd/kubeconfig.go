package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	kubeconfigOutput    string
	kubeconfigCluster   string
	kubeconfigContext   string
	kubeconfigUser      string
	kubeconfigServer    string
	kubeconfigNamespace string
)

var kubeconfigCmd = &cobra.Command{
	Use:   "kubeconfig",
	Short: "Generate kubeconfig for accessing Kubernetes via NetBird",
	Long: `Generate a kubeconfig file that points to a Kubernetes cluster accessible via NetBird.

The generated kubeconfig uses a dummy bearer token for authentication when the 
cluster's auth proxy is running in 'auth' mode. The actual authentication is 
handled by the NetBird network - the auth proxy identifies users by their 
NetBird peer IP and impersonates them in the Kubernetes API.

Example:
  netbird kubeconfig --server https://k8s.example.netbird.cloud:6443 --cluster my-cluster
  netbird kubeconfig --server https://10.100.0.1:6443 -o ~/.kube/netbird-config`,
	RunE: kubeconfigFunc,
}

func init() {
	kubeconfigCmd.Flags().StringVarP(&kubeconfigOutput, "output", "o", "", "Output file path (default: stdout)")
	kubeconfigCmd.Flags().StringVar(&kubeconfigCluster, "cluster", "netbird-cluster", "Cluster name in kubeconfig")
	kubeconfigCmd.Flags().StringVar(&kubeconfigContext, "context", "netbird", "Context name in kubeconfig")
	kubeconfigCmd.Flags().StringVar(&kubeconfigUser, "user", "netbird-user", "User name in kubeconfig")
	kubeconfigCmd.Flags().StringVar(&kubeconfigServer, "server", "", "Kubernetes API server URL (required)")
	kubeconfigCmd.Flags().StringVarP(&kubeconfigNamespace, "namespace", "n", "default", "Default namespace")
	_ = kubeconfigCmd.MarkFlagRequired("server")
}

func kubeconfigFunc(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get current NetBird status to verify connection
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		cmd.PrintErrf("Warning: Could not connect to NetBird daemon: %v\n", err)
		cmd.PrintErrln("Generating kubeconfig anyway, but make sure NetBird is running before using it.")
	} else {
		defer conn.Close()

		resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{})
		if err != nil {
			cmd.PrintErrf("Warning: Could not get NetBird status: %v\n", status.Convert(err).Message())
		} else if resp.Status != "Connected" {
			cmd.PrintErrf("Warning: NetBird is not connected (status: %s)\n", resp.Status)
			cmd.PrintErrln("Make sure to run 'netbird up' before using the generated kubeconfig.")
		}
	}

	kubeconfig := generateKubeconfig(kubeconfigServer, kubeconfigCluster, kubeconfigContext, kubeconfigUser, kubeconfigNamespace)

	if kubeconfigOutput == "" {
		fmt.Println(kubeconfig)
		return nil
	}

	// Expand ~ in path
	if kubeconfigOutput[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		kubeconfigOutput = filepath.Join(home, kubeconfigOutput[2:])
	}

	// Create directory if needed
	dir := filepath.Dir(kubeconfigOutput)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(kubeconfigOutput, []byte(kubeconfig), 0600); err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	cmd.Printf("Kubeconfig written to %s\n", kubeconfigOutput)
	cmd.Printf("\nTo use this kubeconfig:\n")
	cmd.Printf("  export KUBECONFIG=%s\n", kubeconfigOutput)
	cmd.Printf("  kubectl get nodes\n")

	return nil
}

func generateKubeconfig(server, cluster, context, user, namespace string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: %s
  name: %s
contexts:
- context:
    cluster: %s
    namespace: %s
    user: %s
  name: %s
current-context: %s
users:
- name: %s
  user:
    token: netbird-auth-proxy
`, server, cluster, cluster, namespace, user, context, context, user)
}
