package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	certSigningType string
	certWildcard    bool
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage TLS certificates",
	Long:  "Commands to request, inspect, and manage TLS certificates for this peer.",
}

var certRequestCmd = &cobra.Command{
	Use:     "request",
	Short:   "Request a TLS certificate for this peer",
	Example: "  netbird cert request\n  netbird cert request --type acme --wildcard",
	RunE:    certRequestFn,
}

var certStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current certificate status",
	RunE:  certStatusFn,
}

var certTrustCACmd = &cobra.Command{
	Use:   "trust-ca",
	Short: "Install account CA into the OS trust store",
	RunE:  certTrustCAFn,
}

var certUntrustCACmd = &cobra.Command{
	Use:   "untrust-ca",
	Short: "Remove account CA from the OS trust store",
	RunE:  certUntrustCAFn,
}

func init() {
	certRequestCmd.Flags().StringVar(&certSigningType, "type", "internal", "Signing type: internal or acme")
	certRequestCmd.Flags().BoolVar(&certWildcard, "wildcard", false, "Include wildcard SAN (*.fqdn)")
}

func certRequestFn(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	signingType := proto.DaemonCertSigningType_DAEMON_CERT_SIGNING_INTERNAL
	switch strings.ToLower(certSigningType) {
	case "acme":
		signingType = proto.DaemonCertSigningType_DAEMON_CERT_SIGNING_ACME
	case "internal":
		signingType = proto.DaemonCertSigningType_DAEMON_CERT_SIGNING_INTERNAL
	default:
		return fmt.Errorf("invalid signing type %q: must be 'internal' or 'acme'", certSigningType)
	}

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.RequestCertificate(cmd.Context(), &proto.CertificateRequest{
		SigningType: signingType,
		Wildcard:    certWildcard,
	})
	if err != nil {
		return fmt.Errorf("request certificate: %v", status.Convert(err).Message())
	}

	cmd.Println("Certificate issued successfully")
	cmd.Printf("  Certificate: %s\n", resp.CertPath)
	cmd.Printf("  Private key: %s\n", resp.KeyPath)
	if len(resp.DnsNames) > 0 {
		cmd.Printf("  DNS names:   %s\n", strings.Join(resp.DnsNames, ", "))
	}
	if resp.ExpiresAt > 0 {
		cmd.Printf("  Expires:     %s\n", time.Unix(resp.ExpiresAt, 0).Format(time.RFC3339))
	}

	return nil
}

func certStatusFn(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.GetCertificateStatus(cmd.Context(), &proto.CertificateStatusRequest{})
	if err != nil {
		return fmt.Errorf("get certificate status: %v", status.Convert(err).Message())
	}

	if !resp.HasCertificate {
		cmd.Println("No certificate found. Run 'netbird cert request' to obtain one.")
		return nil
	}

	cmd.Println("Certificate status:")
	cmd.Printf("  DNS names:   %s\n", strings.Join(resp.DnsNames, ", "))
	cmd.Printf("  Issuer:      %s\n", resp.Issuer)
	if resp.IssuedAt > 0 {
		cmd.Printf("  Issued:      %s\n", time.Unix(resp.IssuedAt, 0).Format(time.RFC3339))
	}
	if resp.ExpiresAt > 0 {
		cmd.Printf("  Expires:     %s\n", time.Unix(resp.ExpiresAt, 0).Format(time.RFC3339))
	}
	cmd.Printf("  CA trusted:  %v\n", resp.CaTrusted)
	cmd.Printf("  Certificate: %s\n", resp.CertPath)
	cmd.Printf("  Private key: %s\n", resp.KeyPath)

	return nil
}

func certTrustCAFn(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.TrustCA(cmd.Context(), &proto.TrustCARequest{})
	if err != nil {
		return fmt.Errorf("trust CA: %v", status.Convert(err).Message())
	}

	if resp.Success {
		cmd.Printf("CA certificate(s) installed into OS trust store\n")
		for _, fp := range resp.CaFingerprints {
			cmd.Printf("  Fingerprint: %s\n", fp)
		}
	}

	return nil
}

func certUntrustCAFn(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	resp, err := client.UntrustCA(cmd.Context(), &proto.UntrustCARequest{})
	if err != nil {
		return fmt.Errorf("untrust CA: %v", status.Convert(err).Message())
	}

	if resp.Success {
		cmd.Println("CA certificate(s) removed from OS trust store")
	}

	return nil
}
