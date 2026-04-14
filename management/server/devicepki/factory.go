package devicepki

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// NewCA returns the appropriate CA backend for the given account settings.
// The returned CA is ready to use; callers should cache it and recreate it
// only when DeviceAuthSettings change.
//
// managementURL is the externally accessible management server URL (e.g.
// "https://mgmt.example.com"). When non-empty, builtin CAs embed a CDP
// extension in issued certificates using the route /api/device-auth/crl/{token}.
//
// Supported CAType values:
//   - "builtin"   — in-process ECDSA P-256 self-signed root (BuiltinCA)
//   - "vault"     — HashiCorp Vault PKI secrets engine (VaultCA)
//   - "smallstep" — Smallstep CA / step-ca (SmallstepCA)
//   - "scep"      — SCEP protocol server (SCEPCA)
func NewCA(ctx context.Context, settings *types.DeviceAuthSettings, accountID string, st store.Store, managementURL string) (CA, error) {
	if settings == nil {
		return newBuiltinCA(ctx, accountID, st, managementURL)
	}

	switch settings.CAType {
	case "", types.DeviceAuthCATypeBuiltin:
		return newBuiltinCA(ctx, accountID, st, managementURL)

	case types.DeviceAuthCATypeVault:
		cfg, err := parseVaultConfig(settings.CAConfig)
		if err != nil {
			return nil, fmt.Errorf("devicepki: parse vault config: %w", err)
		}
		return NewVaultCA(cfg)

	case types.DeviceAuthCATypeSmallstep:
		cfg, err := parseSmallstepConfig(settings.CAConfig)
		if err != nil {
			return nil, fmt.Errorf("devicepki: parse smallstep config: %w", err)
		}
		return NewSmallstepCA(cfg)

	case types.DeviceAuthCATypeSCEP:
		cfg, err := parseSCEPConfig(settings.CAConfig)
		if err != nil {
			return nil, fmt.Errorf("devicepki: parse SCEP config: %w", err)
		}
		return NewSCEPCA(cfg)

	default:
		return nil, fmt.Errorf("devicepki: unknown CAType %q", settings.CAType)
	}
}

// newBuiltinCA loads the existing builtin CA for an account from the store,
// or creates a new one if none exists yet.
//
// Concurrent creation race: if two goroutines call this simultaneously before
// any CA is persisted, both may generate and save a CA record. The re-read
// after save converges callers to the first saved record, provided the store
// returns results in deterministic order (e.g. by created_at ASC).
// A future improvement is a database-level uniqueness constraint per (account, type)
// to prevent duplicate CA records accumulating.
func newBuiltinCA(ctx context.Context, accountID string, st store.Store, managementURL string) (*BuiltinCA, error) {
	if st != nil {
		cas, err := st.ListTrustedCAs(ctx, store.LockingStrengthNone, accountID)
		if err == nil {
			for _, ca := range cas {
				if ca.KeyPEM != "" {
					cdpURL := buildCDPURL(managementURL, ca.CRLToken)
					loaded, loadErr := LoadBuiltinCA(ca.PEM, ca.KeyPEM, cdpURL)
					if loadErr == nil {
						// Restore in-memory revocation list from persisted records so
						// generated CRLs remain accurate across process restarts.
						loadRevokedFromStore(ctx, loaded, st, accountID)
						return loaded, nil
					}
				}
			}
		}
	}

	// No persisted CA found — generate a new one and immediately persist it.
	certPEM, keyPEM, err := NewBuiltinCA(accountID)
	if err != nil {
		return nil, err
	}

	if st != nil {
		token, tokenErr := generateCRLToken()
		if tokenErr != nil {
			return nil, fmt.Errorf("devicepki: generate CRL token: %w", tokenErr)
		}
		caRecord := types.NewBuiltinTrustedCA(accountID, "NetBird Device CA (auto-generated)", certPEM, keyPEM)
		caRecord.CRLToken = &token
		if saveErr := st.SaveTrustedCA(ctx, store.LockingStrengthUpdate, caRecord); saveErr != nil {
			return nil, fmt.Errorf("devicepki: persist new builtin CA for account %s: %w", accountID, saveErr)
		}

		// Re-read after saving to resolve any concurrent creation: if two goroutines
		// raced to create the first CA, both will have saved a record. We return the
		// first persisted CA so all callers converge to the same key material.
		if cas, listErr := st.ListTrustedCAs(ctx, store.LockingStrengthNone, accountID); listErr == nil {
			for _, ca := range cas {
				if ca.KeyPEM != "" {
					cdpURL := buildCDPURL(managementURL, ca.CRLToken)
					if loaded, loadErr := LoadBuiltinCA(ca.PEM, ca.KeyPEM, cdpURL); loadErr == nil {
						return loaded, nil
					}
				}
			}
		}
	}

	return LoadBuiltinCA(certPEM, keyPEM, "")
}

// loadRevokedFromStore restores the in-memory revocation list of ca from persisted
// DeviceCertificate records. Any record with Revoked=true that has a parseable
// serial and a non-nil RevokedAt time is seeded back into the CA so that the
// generated CRL is correct after a process restart.
//
// Errors are logged but do not block startup — the worst case is an temporarily
// empty CRL until the next restart or explicit Revoke call.
func loadRevokedFromStore(ctx context.Context, ca *BuiltinCA, st store.Store, accountID string) {
	certs, err := st.ListDeviceCertificates(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Warnf("devicepki: could not load revoked certs for account %s: %v (CRL may be incomplete until next restart)", accountID, err)
		return
	}
	var entries revokedEntrySlice
	for _, c := range certs {
		if !c.Revoked || c.RevokedAt == nil {
			continue
		}
		serial := new(big.Int)
		if _, ok := serial.SetString(c.Serial, 10); !ok {
			log.WithContext(ctx).Warnf("devicepki: skipping unparseable serial %q in revocation load", c.Serial)
			continue
		}
		entries = append(entries, revokedEntry{serial: serial, revokedAt: *c.RevokedAt})
	}
	if len(entries) > 0 {
		ca.seedRevoked(entries)
		log.WithContext(ctx).Debugf("devicepki: seeded %d revoked cert(s) from store for account %s", len(entries), accountID)
	}
}

// generateCRLToken returns a 32-byte random hex string suitable for use as a
// CRL distribution point path segment.
func generateCRLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// buildCDPURL constructs the CRL distribution point URL from the management
// server base URL and the CA's random CRL token.
// Returns "" when either argument is nil/empty.
func buildCDPURL(managementURL string, crlToken *string) string {
	if managementURL == "" || crlToken == nil || *crlToken == "" {
		return ""
	}
	return managementURL + "/api/device-auth/crl/" + *crlToken
}

// ─── Config parsers ────────────────────────────────────────────────────────────

func parseVaultConfig(raw string) (VaultConfig, error) {
	var cfg VaultConfig
	if raw == "" {
		return cfg, fmt.Errorf("vault: ca_config is empty")
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, err
	}
	if cfg.Address == "" {
		return cfg, fmt.Errorf("vault: address is required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "pki"
	}
	return cfg, nil
}

func parseSmallstepConfig(raw string) (SmallstepConfig, error) {
	var cfg SmallstepConfig
	if raw == "" {
		return cfg, fmt.Errorf("smallstep: ca_config is empty")
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, err
	}
	if cfg.URL == "" {
		return cfg, fmt.Errorf("smallstep: url is required")
	}
	return cfg, nil
}

func parseSCEPConfig(raw string) (SCEPConfig, error) {
	var cfg SCEPConfig
	if raw == "" {
		return cfg, fmt.Errorf("scep: ca_config is empty")
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, err
	}
	if cfg.URL == "" {
		return cfg, fmt.Errorf("scep: url is required")
	}
	return cfg, nil
}
