//go:build !js

package encryption

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/route53"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/acme"
)

// Route53TLS by default, loads the AWS configuration from the environment.
// env variables: AWS_REGION, AWS_PROFILE, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
type Route53TLS struct {
	DataDir string
	Email   string
	Domains []string
	CA      string
}

func (r *Route53TLS) GetCertificate() (*tls.Config, error) {
	if len(r.Domains) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}

	certmagic.Default.Logger = logger()
	certmagic.Default.Storage = &certmagic.FileStorage{Path: r.DataDir}
	certmagic.DefaultACME.Agreed = true
	if r.Email != "" {
		certmagic.DefaultACME.Email = r.Email
	} else {
		certmagic.DefaultACME.Email = emailFromDomain(r.Domains[0])
	}

	if r.CA == "" {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	} else {
		certmagic.DefaultACME.CA = r.CA
	}

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &route53.Provider{},
		},
	}
	cm := certmagic.NewDefault()
	if err := cm.ManageSync(context.Background(), r.Domains); err != nil {
		log.Errorf("failed to manage certificate: %v", err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		GetCertificate: cm.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}

	return tlsConfig, nil
}

func emailFromDomain(domain string) string {
	if domain == "" {
		return ""
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	if parts[0] == "" {
		return ""
	}
	return fmt.Sprintf("admin@%s.%s", parts[len(parts)-2], parts[len(parts)-1])
}

func logger() *zap.Logger {
	return zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		os.Stderr,
		zap.ErrorLevel,
	))
}
