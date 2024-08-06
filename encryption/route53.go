package encryption

import (
	"context"
	"crypto/tls"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/route53"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/acme"
)

type Route53TLS struct {
	DataDir            string
	Email              string
	AwsAccessKeyID     string
	AwsSecretAccessKey string
	Domains            []string
	CA                 string
}

func (r *Route53TLS) GetCertificate() (*tls.Config, error) {
	certmagic.Default.Logger = logger()
	certmagic.Default.Storage = &certmagic.FileStorage{Path: r.DataDir}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = r.Email
	if r.CA == "" {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	} else {
		certmagic.DefaultACME.CA = r.CA
	}

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &route53.Provider{
				AccessKeyId:     r.AwsAccessKeyID,
				SecretAccessKey: r.AwsSecretAccessKey,
			},
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

func logger() *zap.Logger {
	return zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		os.Stderr,
		zap.ErrorLevel,
	))
}
