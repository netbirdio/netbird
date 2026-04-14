// Package main provides a command-line tool for testing mTLS device certificate
// authentication with a NetBird management server.
//
// It connects to the management gRPC server using a WireGuard key and optionally
// presents a device certificate as a TLS client certificate during the handshake,
// then calls Login (Register) to verify that authentication succeeds or fails.
//
// Usage:
//
//	# Connect WITHOUT client cert (should fail in cert-only mode):
//	go run ./management/cmd/mtls-demo \
//	    -management https://localhost:8443 -setup-key <key> -insecure
//
//	# Connect WITH client cert (should succeed in cert-only mode):
//	go run ./management/cmd/mtls-demo \
//	    -management https://localhost:8443 -setup-key <key> \
//	    -client-cert /tmp/device.pem -client-key /tmp/device.key -insecure
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	mgmURL := flag.String("management", "https://localhost:8443", "Management server URL")
	setupKey := flag.String("setup-key", "", "Reusable setup key for peer registration (required)")
	wgKeyB64 := flag.String("wg-key", "", "Base64-encoded WireGuard private key (generated if empty)")
	clientCertFile := flag.String("client-cert", "", "Path to client certificate PEM file")
	clientKeyFile := flag.String("client-key", "", "Path to client certificate private key PEM file")
	insecure := flag.Bool("insecure", false, "Skip TLS server certificate verification (for self-signed certs)")
	flag.Parse()

	if *setupKey == "" {
		fatalf("-setup-key is required")
	}

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
		fmt.Fprintf(os.Stderr, "[mtls-demo] Generated WireGuard key: pub=%s\n", wgKey.PublicKey())
		fmt.Fprintf(os.Stderr, "[mtls-demo] Save for re-use: -wg-key %s\n\n",
			base64.StdEncoding.EncodeToString(wgKey[:]))
	}

	// Resolve gRPC address from URL.
	mgmAddr := *mgmURL
	useTLS := false
	if u, err := url.Parse(mgmAddr); err == nil && u.Host != "" {
		mgmAddr = u.Host
		useTLS = u.Scheme == "https"
	}

	if !useTLS {
		fatalf("use https:// URL for mTLS testing")
	}

	// Build TLS config.
	tlsCfg := &tls.Config{
		InsecureSkipVerify: *insecure, // #nosec G402 — intentional for test stand with self-signed cert
	}
	if *clientCertFile != "" && *clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(*clientCertFile, *clientKeyFile)
		if err != nil {
			fatalf("load client cert/key: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		fmt.Fprintf(os.Stderr, "[mtls-demo] Using client certificate: %s\n", *clientCertFile)
	} else {
		fmt.Fprintf(os.Stderr, "[mtls-demo] No client certificate provided\n")
	}

	// Dial gRPC with custom TLS.
	fmt.Fprintf(os.Stderr, "[mtls-demo] Connecting to %s (insecure: %v)\n", *mgmURL, *insecure)
	connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)
	conn, err := grpc.DialContext(connCtx, mgmAddr, //nolint:staticcheck
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	connCancel()
	if err != nil {
		fatalf("connect to management: %v", err)
	}

	client := mgmclient.NewClientFromConn(ctx, conn, wgKey)
	defer client.Close()
	fmt.Fprintf(os.Stderr, "[mtls-demo] Connected.\n\n")

	// Call Register (Login) to test authentication.
	sysInfo := &system.Info{
		GoOS:           runtime.GOOS,
		Hostname:       "mtls-demo",
		NetbirdVersion: "dev",
	}

	fmt.Fprintf(os.Stderr, "[mtls-demo] Sending Login (Register) request with setup key...\n")
	_, loginErr := client.Register(*setupKey, "", sysInfo, nil, nil)
	if loginErr != nil {
		fmt.Fprintf(os.Stderr, "[mtls-demo] Login FAILED: %v\n", loginErr)
		fmt.Fprintln(os.Stdout, "RESULT: DENIED")
		os.Exit(1) //nolint:gocritic // demo tool — defer cleanup intentionally skipped on fatal error
	}

	fmt.Fprintf(os.Stderr, "[mtls-demo] Login SUCCEEDED\n")
	fmt.Fprintln(os.Stdout, "RESULT: ALLOWED")
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
	os.Exit(1)
}
