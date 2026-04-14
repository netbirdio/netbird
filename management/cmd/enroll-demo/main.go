// Package main provides a command-line tool for testing device certificate
// enrollment with a NetBird management server that has the feature/tpm-cert-auth
// branch deployed.
//
// The tool generates a throw-away WireGuard key pair and an ECDSA P-256 CSR,
// registers the peer with the management server using a setup key,
// and submits an EnrollDevice gRPC call.  The admin can then approve the
// returned enrollment_id via the HTTP API or via the demo-enrollment.sh script.
//
// Usage:
//
//	# Submit a new enrollment request (generates new WireGuard key):
//	go run ./management/cmd/enroll-demo \
//	    -management http://localhost:8080 \
//	    -setup-key <reusable-setup-key>
//
//	# Submit using a saved WireGuard key (idempotent):
//	go run ./management/cmd/enroll-demo \
//	    -management http://localhost:8080 \
//	    -setup-key <reusable-setup-key> \
//	    -wg-key <base64-wg-private-key>
//
//	# Poll the status of an existing enrollment:
//	go run ./management/cmd/enroll-demo \
//	    -management http://localhost:8080 \
//	    -enrollment-id <id> \
//	    -wg-key <base64-wg-private-key>
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/client/system"
	mgmclient "github.com/netbirdio/netbird/shared/management/client"
)

func main() {
	mgmURL := flag.String("management", "http://localhost:8080", "Management server URL")
	setupKey := flag.String("setup-key", "", "Reusable setup key for peer registration (required)")
	enrollID := flag.String("enrollment-id", "", "Poll status of an existing enrollment ID (instead of creating new)")
	wgKeyB64 := flag.String("wg-key", "", "Base64-encoded WireGuard private key (generated if empty)")
	saveKeyPath := flag.String("save-device-key", "", "If set, save the CSR private key to this file after enrollment (PEM PKCS8)")
	tlsEnabled := flag.Bool("tls", false, "Connect to management using TLS (use for https:// URLs)")
	insecure := flag.Bool("insecure", false, "Skip TLS server certificate verification (for self-signed certs on test stands)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Resolve WireGuard key.
	var wgKey wgtypes.Key
	if *wgKeyB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(*wgKeyB64)
		if err != nil {
			fatalf("decode -wg-key: %v", err)
		}
		wgKey, err = wgtypes.NewKey(raw)
		if err != nil {
			fatalf("parse -wg-key: %v", err)
		}
	} else {
		var err error
		wgKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			fatalf("generate WireGuard key: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[demo] Generated WireGuard key:  pub=%s\n", wgKey.PublicKey())
		fmt.Fprintf(os.Stderr, "[demo] Save for re-use:           -wg-key %s\n\n",
			base64.StdEncoding.EncodeToString(wgKey[:]))
	}

	// Resolve the management gRPC address: NewClient expects "host:port",
	// not a full URL with scheme.  Accept both forms for convenience.
	mgmAddr := *mgmURL
	useTLS := *tlsEnabled
	if u, err := url.Parse(mgmAddr); err == nil && u.Host != "" {
		mgmAddr = u.Host
		if u.Scheme == "https" {
			useTLS = true
		}
	}

	// Connect to management gRPC.
	fmt.Fprintf(os.Stderr, "[demo] Connecting to management: %s (gRPC addr: %s, TLS: %v, insecure: %v)\n", *mgmURL, mgmAddr, useTLS, *insecure)
	var client *mgmclient.GrpcClient
	if useTLS && *insecure {
		// Build connection with InsecureSkipVerify for test stands with self-signed certs.
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — intentional for test stand with self-signed cert
		}
		connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
		conn, dialErr := grpc.DialContext(connCtx, mgmAddr, //nolint:staticcheck
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
			grpc.WithBlock(),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:    30 * time.Second,
				Timeout: 10 * time.Second,
			}),
		)
		connCancel()
		if dialErr != nil {
			fatalf("connect to management (insecure TLS): %v", dialErr)
		}
		client = mgmclient.NewClientFromConn(ctx, conn, wgKey)
		defer client.Close()
	} else {
		var err error
		client, err = mgmclient.NewClient(ctx, mgmAddr, wgKey, useTLS)
		if err != nil {
			fatalf("connect to management: %v", err)
		}
		defer client.Close()
	}
	fmt.Fprintf(os.Stderr, "[demo] Connected.\n\n")

	// Poll-only mode.
	if *enrollID != "" {
		pollStatus(client, *enrollID)
		return
	}

	if *setupKey == "" {
		fatalf("-setup-key is required for new enrollments.\n\n" +
			"  Usage: -setup-key <reusable-setup-key>")
	}

	registerPeer(client, *setupKey)
	submitEnrollment(client, wgKey, *saveKeyPath)
}

// registerPeer performs a Login (peer registration) so the management server
// recognises the WireGuard key before we call EnrollDevice.
func registerPeer(client *mgmclient.GrpcClient, setupKey string) {
	sysInfo := &system.Info{
		GoOS:           runtime.GOOS,
		Hostname:       "enroll-demo",
		NetbirdVersion: "dev",
	}

	fmt.Fprintf(os.Stderr, "[demo] Registering peer with setup key...\n")
	_, err := client.Register(setupKey, "", sysInfo, nil, nil)
	if err != nil {
		fatalf("Register (peer login): %v", err)
	}
	fmt.Fprintf(os.Stderr, "[demo] Peer registered.\n\n")
}

// submitEnrollment generates a CSR and calls EnrollDevice.
// If saveKeyPath is set, the CSR private key is saved as a PEM file so the issued
// certificate can later be used for mTLS connections.
func submitEnrollment(client *mgmclient.GrpcClient, wgKey wgtypes.Key, saveKeyPath string) {
	csrPEM, privKey, err := generateCSR(wgKey.PublicKey().String())
	if err != nil {
		fatalf("generate CSR: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[demo] Submitting enrollment (Mode A — admin approval required)...\n")

	resp, err := client.EnrollDevice(csrPEM, `{"hostname":"enroll-demo"}`, nil)
	if err != nil {
		fatalf("EnrollDevice: %v", err)
	}

	// Save the CSR private key so the issued certificate can later be used for mTLS.
	if saveKeyPath != "" {
		keyDER, marshalErr := x509.MarshalECPrivateKey(privKey)
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "[demo] WARNING: could not marshal private key: %v\n", marshalErr)
		} else {
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
			if writeErr := os.WriteFile(saveKeyPath, keyPEM, 0600); writeErr != nil {
				fmt.Fprintf(os.Stderr, "[demo] WARNING: could not save private key to %s: %v\n", saveKeyPath, writeErr)
			} else {
				fmt.Fprintf(os.Stderr, "[demo] CSR private key saved to: %s\n", saveKeyPath)
			}
		}
	}

	printJSON(map[string]interface{}{
		"enrollment_id":   resp.EnrollmentId,
		"status":          resp.Status,
		"device_cert_pem": resp.DeviceCertPem,
		"reason":          resp.Reason,
		"wg_public_key":   wgKey.PublicKey().String(),
	})

	if resp.Status == "pending" {
		fmt.Fprintf(os.Stderr, "\n[demo] Enrollment is pending admin approval.\n")
		fmt.Fprintf(os.Stderr, "       Approve it:\n")
		fmt.Fprintf(os.Stderr, "         ENROLLMENT_ID=%s NETBIRD_TOKEN=<token> \\\n", resp.EnrollmentId)
		fmt.Fprintf(os.Stderr, "           bash scripts/demo-enrollment.sh approve\n\n")
		fmt.Fprintf(os.Stderr, "       Then poll status:\n")
		fmt.Fprintf(os.Stderr, "         go run ./management/cmd/enroll-demo \\\n")
		fmt.Fprintf(os.Stderr, "           -enrollment-id %s \\\n", resp.EnrollmentId)
		fmt.Fprintf(os.Stderr, "           -wg-key <your-wg-key-b64>\n")
		if saveKeyPath != "" {
			fmt.Fprintf(os.Stderr, "           -tls\n")
		}
	}
}

// pollStatus calls GetEnrollmentStatus and prints the result.
func pollStatus(client *mgmclient.GrpcClient, enrollmentID string) {
	fmt.Fprintf(os.Stderr, "[demo] Polling status for enrollment: %s\n\n", enrollmentID)
	resp, err := client.GetEnrollmentStatus(enrollmentID)
	if err != nil {
		fatalf("GetEnrollmentStatus: %v", err)
	}

	printJSON(map[string]interface{}{
		"enrollment_id":   resp.EnrollmentId,
		"status":          resp.Status,
		"device_cert_pem": resp.DeviceCertPem,
		"reason":          resp.Reason,
	})

	if resp.Status == "approved" && resp.DeviceCertPem != "" {
		fmt.Fprintf(os.Stderr, "\n[demo] Certificate issued! Subject:\n")
		printCertSubject(resp.DeviceCertPem)
	}
}

// generateCSR creates an ECDSA P-256 key and a PKCS#10 CSR with the given CN.
// Returns the PEM-encoded CSR, the private key (for saving), and any error.
func generateCSR(cn string) (string, *ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, privKey)
	if err != nil {
		return "", nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM), privKey, nil
}

// printCertSubject parses a PEM cert and prints its Subject line.
func printCertSubject(certPEM string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "  Subject:  %s\n", cert.Subject)
	fmt.Fprintf(os.Stderr, "  Issuer:   %s\n", cert.Issuer)
	fmt.Fprintf(os.Stderr, "  NotAfter: %s\n", cert.NotAfter.Format(time.RFC3339))
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatalf("encode JSON: %v", err)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
	os.Exit(1)
}
