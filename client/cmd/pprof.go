package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	pprofPort    string
	pprofCertFile string
	pprofKeyFile  string
)

var pprofCmd = &cobra.Command{
	Use:   "pprof",
	Short: "Start pprof server with TLS support",
	RunE: func(cmd *cobra.Command, args []string) error {
		return startPprofServer()
	},
}

func init() {
	pprofCmd.Flags().StringVar(&pprofPort, "port", "6060", "pprof server port")
	pprofCmd.Flags().StringVar(&pprofCertFile, "cert-file", "", "TLS certificate file path")
	pprofCmd.Flags().StringVar(&pprofKeyFile, "key-file", "", "TLS private key file path")
	rootCmd.AddCommand(pprofCmd)
}

func startPprofServer() error {
	addr := ":" + pprofPort
	
	// If no certificate files provided, generate self-signed certificate
	if pprofCertFile == "" || pprofKeyFile == "" {
		log.Info("No TLS certificates provided, generating self-signed certificate for pprof server")
		cert, key, err := generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		
		tlsCert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("failed to create TLS certificate: %w", err)
		}
		
		server := &http.Server{
			Addr: addr,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				MinVersion:   tls.VersionTLS12,
			},
		}
		
		log.Infof("Starting pprof server with self-signed TLS on https://localhost%s/debug/pprof/", addr)
		return server.ListenAndServeTLS("", "")
	}
	
	log.Infof("Starting pprof server with TLS on https://localhost%s/debug/pprof/", addr)
	return http.ListenAndServeTLS(addr, pprofCertFile, pprofKeyFile, nil)
}

func generateSelfSignedCert() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	
	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NetBird Pprof"},
			Country:      []string{"US"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	
	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	
	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	
	return certPEM, keyPEM, nil
}
