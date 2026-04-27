// Package legoclient is the shared Lego + Cloudflare DNS-01 helper used by
// the dns01 spike CLI and by LegoBackend. It is intentionally small: it
// exists to prove the integration shape, not to be production-ready.
//
// SPIKE NOTE: production work (p1-plan.md Wave 2) will replace much of
// this with: encrypted credential storage (not env vars), pluggable
// providers via a registry, the existing distributed locker, and proper
// renewal lifecycle. See roadmap.md and p1-plan.md for the full story.
package legoclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/sirupsen/logrus"
)

// Config configures a spike Lego client.
type Config struct {
	// StorageDir is where ACME account state and issued certs are persisted.
	StorageDir string
	// ACMEDirectoryURL is the ACME directory URL (e.g. Let's Encrypt staging).
	ACMEDirectoryURL string
	// AccountEmail is the ACME account email.
	AccountEmail string
	// CloudflareAPIToken is a scoped Cloudflare API token with Zone:DNS:Edit
	// for the target zone. Do NOT use the global API key.
	CloudflareAPIToken string
	// Logger is optional; defaults to logrus.StandardLogger().
	Logger *log.Logger
}

// Client wraps a configured *lego.Client with persistence.
type Client struct {
	cfg    Config
	user   *acmeUser
	lego   *lego.Client
	logger *log.Logger
}

// New configures a Lego client for DNS-01 via Cloudflare. ACME account state
// (private key + registration) is persisted under cfg.StorageDir so reruns
// are idempotent.
func New(cfg Config) (*Client, error) {
	if cfg.AccountEmail == "" {
		return nil, fmt.Errorf("account email is required")
	}
	if cfg.CloudflareAPIToken == "" {
		return nil, fmt.Errorf("cloudflare API token is required")
	}
	if cfg.ACMEDirectoryURL == "" {
		return nil, fmt.Errorf("ACME directory URL is required")
	}
	if cfg.StorageDir == "" {
		return nil, fmt.Errorf("storage dir is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.StandardLogger()
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("create storage dir %q: %w", cfg.StorageDir, err)
	}

	user, err := loadOrCreateUser(cfg.StorageDir, cfg.AccountEmail)
	if err != nil {
		return nil, fmt.Errorf("load/create ACME user: %w", err)
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.ACMEDirectoryURL
	legoCfg.Certificate.KeyType = certcrypto.RSA2048

	cli, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("build lego client: %w", err)
	}

	cfCfg := cloudflare.NewDefaultConfig()
	cfCfg.AuthToken = cfg.CloudflareAPIToken
	cfProvider, err := cloudflare.NewDNSProviderConfig(cfCfg)
	if err != nil {
		return nil, fmt.Errorf("build cloudflare provider: %w", err)
	}
	if err := cli.Challenge.SetDNS01Provider(cfProvider); err != nil {
		return nil, fmt.Errorf("set DNS-01 provider: %w", err)
	}

	if user.Registration == nil {
		reg, err := cli.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register ACME account: %w", err)
		}
		user.Registration = reg
		if err := saveUser(cfg.StorageDir, user); err != nil {
			return nil, fmt.Errorf("persist ACME registration: %w", err)
		}
		cfg.Logger.Infof("[legoclient] registered new ACME account for %s", cfg.AccountEmail)
	} else {
		cfg.Logger.Infof("[legoclient] reusing existing ACME account for %s", cfg.AccountEmail)
	}

	return &Client{cfg: cfg, user: user, lego: cli, logger: cfg.Logger}, nil
}

// IssueCertificate obtains a cert for the given FQDN via DNS-01 and writes
// the cert chain and key to cfg.StorageDir as <fqdn>.crt and <fqdn>.key.
// Idempotent: if both files already exist, returns nil without re-issuing.
func (c *Client) IssueCertificate(_ context.Context, fqdn string) error {
	if fqdn == "" {
		return fmt.Errorf("fqdn is required")
	}
	certPath := filepath.Join(c.cfg.StorageDir, fqdn+".crt")
	keyPath := filepath.Join(c.cfg.StorageDir, fqdn+".key")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			c.logger.Infof("[legoclient] cert + key for %s already exist; skipping issuance", fqdn)
			return nil
		}
	}

	c.logger.Infof("[legoclient] requesting cert for %s via DNS-01 (a TXT record will be set & cleaned up at Cloudflare)", fqdn)
	res, err := c.lego.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{fqdn},
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("obtain cert for %s: %w", fqdn, err)
	}

	if err := os.WriteFile(certPath, res.Certificate, 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, res.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	c.logger.Infof("[legoclient] cert written to %s, key written to %s", certPath, keyPath)
	return nil
}

// --- Internal: ACME user (implements registration.User) -------------------

type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

const (
	accountKeyFile  = "account.key"
	accountJSONFile = "account.json"
)

func loadOrCreateUser(dir, email string) (*acmeUser, error) {
	keyPath := filepath.Join(dir, accountKeyFile)
	regPath := filepath.Join(dir, accountJSONFile)

	key, err := loadOrCreateECDSAKey(keyPath)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{Email: email, key: key}

	regBytes, err := os.ReadFile(regPath)
	if err != nil {
		if os.IsNotExist(err) {
			return user, nil
		}
		return nil, fmt.Errorf("read account registration: %w", err)
	}
	if err := json.Unmarshal(regBytes, user); err != nil {
		return nil, fmt.Errorf("unmarshal account registration: %w", err)
	}
	return user, nil
}

func saveUser(dir string, user *acmeUser) error {
	regPath := filepath.Join(dir, accountJSONFile)
	b, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal account: %w", err)
	}
	return os.WriteFile(regPath, b, 0o600)
}

func loadOrCreateECDSAKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM in %q", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ECDSA key from %q: %w", path, err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write account key: %w", err)
	}
	return key, nil
}
